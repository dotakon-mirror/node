use crate::clock::Clock;
use crate::db;
use crate::dotakon::{self, node_service_v1_server::NodeServiceV1};
use crate::keys;
use crate::net;
use crate::proto;
use crate::tree::{self, AccountInfo};
use crate::utils;
use crate::version;
use anyhow::Context;
use pasta_curves::{pallas::Point, pallas::Scalar};
use primitive_types::H256;
use rand_core::{OsRng, RngCore};
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::{time::Duration, time::sleep};
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status, Streaming};

fn get_random() -> H256 {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    H256::from_slice(&bytes)
}

pub struct NodeServiceImpl {
    key_manager: Arc<keys::KeyManager>,
    identity: dotakon::node_identity::Payload,
    db: db::Db,
    cancel: CancellationToken,
}

impl NodeServiceImpl {
    fn get_protocol_version() -> dotakon::ProtocolVersion {
        dotakon::ProtocolVersion {
            major: Some(version::PROTOCOL_VERSION_MAJOR),
            minor: Some(version::PROTOCOL_VERSION_MINOR),
            build: Some(version::PROTOCOL_VERSION_BUILD),
        }
    }

    fn make_node_identity(
        chain_id: u64,
        timestamp: SystemTime,
        key_manager: &keys::KeyManager,
        location: dotakon::GeographicalLocation,
        public_address: &str,
        grpc_port: u16,
        http_port: u16,
    ) -> dotakon::node_identity::Payload {
        dotakon::node_identity::Payload {
            protocol_version: Some(Self::get_protocol_version()),
            chain_id: Some(chain_id),
            account_address: Some(proto::pallas_scalar_to_bytes32(
                key_manager.wallet_address(),
            )),
            location: Some(location),
            network_address: Some(public_address.to_owned()),
            grpc_port: Some(grpc_port.into()),
            http_port: Some(http_port.into()),
            timestamp: Some(timestamp.into()),
        }
    }

    fn new<const N: usize>(
        clock: Arc<dyn Clock>,
        key_manager: Arc<keys::KeyManager>,
        location: dotakon::GeographicalLocation,
        chain_id: u64,
        public_address: &str,
        initial_accounts: [(Scalar, AccountInfo); N],
        grpc_port: u16,
        http_port: u16,
    ) -> anyhow::Result<Arc<Self>> {
        println!("Public key: {:#x}", key_manager.compressed_public_key());
        println!(
            "Public key (Ed25519): {:#x}",
            key_manager.compressed_public_key_25519()
        );
        println!(
            "Wallet address: {}",
            utils::format_wallet_address(key_manager.wallet_address())
        );
        let identity = Self::make_node_identity(
            chain_id,
            clock.now(),
            &key_manager,
            location,
            public_address,
            grpc_port,
            http_port,
        );
        let (identity_payload, identity_signature) =
            key_manager.sign_message(&identity, get_random())?;
        let service = Arc::new(Self {
            key_manager,
            identity,
            db: db::Db::new(
                clock,
                chain_id,
                dotakon::NodeIdentity {
                    payload: Some(identity_payload),
                    signature: Some(identity_signature),
                },
                initial_accounts,
            )?,
            cancel: CancellationToken::new(),
        });
        service.clone().start_block_timer();
        Ok(service)
    }

    fn get_client_public_key<M>(&self, request: &Request<M>) -> anyhow::Result<Point> {
        let info = request
            .extensions()
            .get::<net::ConnectionInfo>()
            .context("certificate not found")?;
        Ok(info.peer_public_key())
    }

    fn get_client_wallet_address<M>(&self, request: &Request<M>) -> anyhow::Result<Scalar> {
        let info = request
            .extensions()
            .get::<net::ConnectionInfo>()
            .context("certificate not found")?;
        Ok(info.peer_wallet_address())
    }

    fn sign_message<M: prost::Message + prost::Name>(
        &self,
        message: &M,
    ) -> anyhow::Result<(prost_types::Any, dotakon::Signature)> {
        self.key_manager.sign_message(message, get_random())
    }

    fn start_block_timer(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = sleep(Duration::from_secs(10)) => {
                        let block = self.db.close_block().await;
                        println!("mined block {}: {:#x}", block.number(), utils::pallas_scalar_to_u256(block.hash()));
                    },
                    _ = self.cancel.cancelled() => {
                        break;
                    },
                }
            }
        });
    }

    async fn get_block_impl(
        &self,
        request: &dotakon::GetBlockRequest,
    ) -> Result<db::BlockInfo, Status> {
        match request.block_hash {
            Some(block_hash) => {
                let block_hash = proto::pallas_scalar_from_bytes32(&block_hash)
                    .map_err(|_| Status::invalid_argument("invalid block hash"))?;
                self.db
                    .get_block_by_hash(block_hash)
                    .await
                    .context(format!(
                        "block hash {:#x} not found",
                        utils::pallas_scalar_to_u256(block_hash)
                    ))
                    .map_err(|error| Status::not_found(error.to_string()))
            }
            None => Ok(self.db.get_latest_block().await),
        }
    }

    async fn get_account_impl(
        &self,
        request: &dotakon::GetAccountRequest,
    ) -> Result<(db::BlockInfo, tree::AccountProof), Status> {
        let account_address = proto::pallas_scalar_from_bytes32(
            &request
                .account_address
                .context("missing account address field")
                .map_err(|error| Status::invalid_argument(error.to_string()))?,
        )
        .map_err(|_| Status::invalid_argument("invalid account address"))?;
        match request.block_hash {
            Some(block_hash) => {
                let block_hash = proto::pallas_scalar_from_bytes32(&block_hash)
                    .map_err(|_| Status::invalid_argument("invalid block hash"))?;
                self.db
                    .get_account_info(account_address, block_hash)
                    .await
                    .map_err(|_| {
                        Status::not_found(format!(
                            "account address {:#x} not found at block {:#x}",
                            utils::pallas_scalar_to_u256(account_address),
                            utils::pallas_scalar_to_u256(block_hash)
                        ))
                    })
            }
            None => self
                .db
                .get_latest_account_info(account_address)
                .await
                .map_err(|_| {
                    Status::not_found(format!(
                        "account address {:#x} not found",
                        utils::pallas_scalar_to_u256(account_address)
                    ))
                }),
        }
    }

    async fn get_transaction_impl(
        &self,
        request: &dotakon::GetTransactionRequest,
    ) -> Result<dotakon::BoundTransaction, Status> {
        let transaction_hash = match request.transaction_hash {
            Some(hash) => proto::pallas_scalar_from_bytes32(&hash)
                .map_err(|_| Status::invalid_argument("invalid transaction hash"))?,
            None => return Err(Status::invalid_argument("transaction hash field missing")),
        };
        match self.db.get_transaction(transaction_hash).await {
            Some(transaction) => Ok(dotakon::BoundTransaction {
                parent_transaction_hash: Some(proto::pallas_scalar_to_bytes32(
                    transaction.parent_hash(),
                )),
                transaction: Some(transaction.diff()),
            }),
            None => Err(Status::not_found(format!(
                "transaction hash {:#x} not found",
                utils::pallas_scalar_to_u256(transaction_hash)
            ))),
        }
    }
}

impl Drop for NodeServiceImpl {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub struct NodeService {
    inner: Arc<NodeServiceImpl>,
}

impl NodeService {
    pub fn new<const N: usize>(
        clock: Arc<dyn Clock>,
        key_manager: Arc<keys::KeyManager>,
        location: dotakon::GeographicalLocation,
        chain_id: u64,
        public_address: &str,
        initial_accounts: [(Scalar, AccountInfo); N],
        grpc_port: u16,
        http_port: u16,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            inner: NodeServiceImpl::new(
                clock,
                key_manager,
                location,
                chain_id,
                public_address,
                initial_accounts,
                grpc_port,
                http_port,
            )?,
        })
    }

    fn sign_message<M: prost::Message + prost::Name>(
        &self,
        message: &M,
    ) -> anyhow::Result<(prost_types::Any, dotakon::Signature)> {
        self.inner.sign_message(message)
    }
}

#[tonic::async_trait]
impl NodeServiceV1 for NodeService {
    async fn get_identity(
        &self,
        _request: Request<dotakon::GetIdentityRequest>,
    ) -> Result<Response<dotakon::NodeIdentity>, Status> {
        let (payload, signature) = self
            .sign_message(&self.inner.identity)
            .map_err(|_| Status::internal("signature error"))?;
        Ok(Response::new(dotakon::NodeIdentity {
            payload: Some(payload),
            signature: Some(signature),
        }))
    }

    async fn get_block(
        &self,
        request: Request<dotakon::GetBlockRequest>,
    ) -> Result<Response<dotakon::GetBlockResponse>, Status> {
        let block_info = self.inner.get_block_impl(request.get_ref()).await?;
        let descriptor = block_info.encode();
        let (payload, signature) = self
            .sign_message(&descriptor)
            .map_err(|_| Status::internal("signature error"))?;
        Ok(Response::new(dotakon::GetBlockResponse {
            payload: Some(payload),
            signature: Some(signature),
        }))
    }

    async fn get_topology(
        &self,
        _request: Request<dotakon::GetTopologyRequest>,
    ) -> Result<Response<dotakon::NetworkTopology>, Status> {
        Ok(Response::new(dotakon::NetworkTopology { cluster: vec![] }))
    }

    async fn get_account(
        &self,
        request: Request<dotakon::GetAccountRequest>,
    ) -> Result<Response<dotakon::GetAccountResponse>, Status> {
        let (block_info, proof) = self.inner.get_account_impl(request.get_ref()).await?;
        let payload = proof
            .encode(block_info.encode())
            .map_err(|_| Status::internal("internal error"))?;
        let (payload, signature) = self
            .sign_message(&payload)
            .map_err(|_| Status::internal("signature error"))?;
        Ok(Response::new(dotakon::GetAccountResponse {
            payload: Some(payload),
            signature: Some(signature),
        }))
    }

    async fn get_transaction(
        &self,
        request: Request<dotakon::GetTransactionRequest>,
    ) -> Result<Response<dotakon::GetTransactionResponse>, Status> {
        let transaction = self.inner.get_transaction_impl(request.get_ref()).await?;
        let (payload, signature) = self
            .sign_message(&transaction)
            .map_err(|_| Status::internal("internal error"))?;
        Ok(Response::new(dotakon::GetTransactionResponse {
            payload: Some(payload),
            signature: Some(signature),
        }))
    }

    async fn broadcast_transaction(
        &self,
        request: Request<dotakon::BroadcastTransactionRequest>,
    ) -> Result<Response<dotakon::BroadcastTransactionResponse>, Status> {
        let transaction = match &request.get_ref().transaction {
            Some(transaction) => Ok(transaction),
            None => Err(Status::invalid_argument("missing transaction data")),
        }?;
        let payload = match &transaction.payload {
            Some(payload) => Ok(payload),
            None => Err(Status::invalid_argument("missing transaction payload")),
        }?;
        let signature = match &transaction.signature {
            Some(signature) => Ok(signature),
            None => Err(Status::invalid_argument("missing transaction signature")),
        }?;
        keys::KeyManager::verify_signed_message(&payload, &signature)
            .map_err(|_| Status::invalid_argument("invalid transaction signature"))?;
        self.inner
            .db
            .add_transaction(transaction)
            .await
            .map_err(|_| Status::internal("transaction error"))?;
        Ok(Response::new(dotakon::BroadcastTransactionResponse {}))
    }

    async fn broadcast_new_block(
        &self,
        _request: Request<dotakon::BroadcastBlockRequest>,
    ) -> Result<Response<dotakon::BroadcastBlockResponse>, Status> {
        todo!()
    }

    type RefactorNetworkStream =
        Pin<Box<dyn Stream<Item = Result<dotakon::NetworkRefactoringResponse, Status>> + Send>>;

    async fn refactor_network(
        &self,
        _request: Request<Streaming<dotakon::NetworkRefactoringRequest>>,
    ) -> Result<Response<Self::RefactorNetworkStream>, Status> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::test::MockClock;
    use crate::dotakon::{
        self, node_service_v1_client::NodeServiceV1Client,
        node_service_v1_server::NodeServiceV1Server,
    };
    use crate::net;
    use crate::ssl;
    use ff::Field;
    use tokio::{sync::Notify, task::JoinHandle, task::yield_now};
    use tonic::transport::{Channel, Server};

    const TEST_CHAIN_ID: u64 = 42;

    struct TestFixture {
        clock: Arc<MockClock>,
        server_key_manager: Arc<keys::KeyManager>,
        client_key_manager: Arc<keys::KeyManager>,
        server_handle: JoinHandle<()>,
        client: NodeServiceV1Client<Channel>,
    }

    impl TestFixture {
        async fn new<const N: usize>(
            location: dotakon::GeographicalLocation,
            initial_accounts: [(Scalar, AccountInfo); N],
        ) -> anyhow::Result<Self> {
            let nonce = H256::from_slice(&[
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 0, 0,
            ]);

            let (server_secret_key, _, _) = utils::testing_keys1();
            let server_key_manager = Arc::new(keys::KeyManager::new(server_secret_key));
            let server_certificate = Arc::new(
                ssl::generate_certificate(server_key_manager.clone(), "server".to_string(), nonce)
                    .unwrap(),
            );

            let (client_secret_key, _, _) = utils::testing_keys2();
            let client_key_manager = Arc::new(keys::KeyManager::new(client_secret_key));
            let client_certificate = Arc::new(
                ssl::generate_certificate(client_key_manager.clone(), "client".to_string(), nonce)
                    .unwrap(),
            );

            let clock: Arc<MockClock> = Arc::new(MockClock::new(
                SystemTime::UNIX_EPOCH + Duration::from_secs(71104),
            ));

            let service = NodeServiceV1Server::new(
                NodeService::new(
                    clock.clone(),
                    server_key_manager.clone(),
                    location,
                    TEST_CHAIN_ID,
                    "localhost",
                    initial_accounts,
                    4443,
                    8080,
                )
                .unwrap(),
            );

            let (server_stream, client_stream) = tokio::io::duplex(4096);

            let server_key_manager_clone = server_key_manager.clone();

            let server_ready = Arc::new(Notify::new());
            let start_client = server_ready.clone();
            let server_handle = tokio::task::spawn(async move {
                let future = Server::builder().add_service(service).serve_with_incoming(
                    net::IncomingWithMTls::new(
                        Arc::new(net::test::MockListener::new(server_stream)),
                        server_key_manager_clone,
                        server_certificate,
                    )
                    .await
                    .unwrap(),
                );
                server_ready.notify_one();
                future.await.unwrap();
            });
            start_client.notified().await;

            let (channel, _) = net::test::mock_connect_with_mtls(
                client_stream,
                client_key_manager.clone(),
                client_certificate.clone(),
            )
            .await
            .unwrap();
            let client = NodeServiceV1Client::new(channel);

            Ok(Self {
                clock,
                server_key_manager,
                client_key_manager,
                server_handle,
                client,
            })
        }

        async fn with_initial_balances<const N: usize>(
            initial_balances: [(Scalar, Scalar); N],
        ) -> anyhow::Result<Self> {
            Self::new(
                dotakon::GeographicalLocation {
                    latitude: Some(71i32),
                    longitude: Some(104u32),
                },
                initial_balances
                    .map(|(address, balance)| (address, AccountInfo::with_balance(balance))),
            )
            .await
        }

        async fn default() -> anyhow::Result<Self> {
            Self::with_initial_balances([]).await
        }

        fn clock(&self) -> &Arc<MockClock> {
            &self.clock
        }
    }

    impl Drop for TestFixture {
        fn drop(&mut self) {
            self.server_handle.abort();
        }
    }

    fn default_genesis_block_hash() -> Scalar {
        utils::u256_to_pallas_scalar(
            "0x279760377f1ebc7931e1804663b301f687630a6144947353b710ed811bfcb2c5"
                .parse()
                .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn test_identity() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;

        let response = client
            .get_identity(dotakon::GetIdentityRequest::default())
            .await
            .unwrap();
        let identity = response.get_ref();
        let payload = identity.payload.as_ref().unwrap();
        assert!(
            keys::KeyManager::verify_signed_message(payload, identity.signature.as_ref().unwrap())
                .is_ok()
        );
        let payload = payload.to_msg::<dotakon::node_identity::Payload>().unwrap();

        let protocol_version = &payload.protocol_version.unwrap();
        assert_eq!(
            protocol_version.major.unwrap(),
            version::PROTOCOL_VERSION_MAJOR
        );
        assert_eq!(
            protocol_version.minor.unwrap(),
            version::PROTOCOL_VERSION_MINOR
        );
        assert_eq!(
            protocol_version.build.unwrap(),
            version::PROTOCOL_VERSION_BUILD
        );

        assert_eq!(
            proto::pallas_scalar_from_bytes32(&payload.account_address.unwrap()).unwrap(),
            fixture.server_key_manager.wallet_address()
        );

        let location = &payload.location.unwrap();
        assert_eq!(location.latitude.unwrap(), 71i32);
        assert_eq!(location.longitude.unwrap(), 104u32);

        assert_eq!(payload.network_address.unwrap(), "localhost");
        assert_eq!(payload.grpc_port.unwrap(), 4443u32);
        assert_eq!(payload.http_port.unwrap(), 8080u32);
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_genesis_block() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;

        let response = client
            .get_block(dotakon::GetBlockRequest {
                block_hash: Some(proto::pallas_scalar_to_bytes32(default_genesis_block_hash())),
            })
            .await
            .unwrap();
        let response = response.get_ref();
        let payload = response.payload.as_ref().unwrap();
        assert!(
            keys::KeyManager::verify_signed_message(
                &payload,
                &response.signature.as_ref().unwrap()
            )
            .is_ok()
        );
        let payload = payload.to_msg::<dotakon::BlockDescriptor>().unwrap();

        assert_eq!(
            proto::pallas_scalar_from_bytes32(&payload.block_hash.unwrap()).unwrap(),
            default_genesis_block_hash()
        );
        assert_eq!(payload.block_number.unwrap(), 0);
        assert_eq!(
            proto::pallas_scalar_from_bytes32(&payload.previous_block_hash.unwrap()).unwrap(),
            Scalar::ZERO
        );
        assert_eq!(
            proto::pallas_scalar_from_bytes32(&payload.network_topology_root_hash.unwrap())
                .unwrap(),
            utils::parse_pallas_scalar(
                "0x3f75bfd1de06f77cce4d43d38ffac77eac6a8de697cf3b2a798bc19f1cb1c2b2"
            )
        );
        assert_eq!(
            proto::pallas_scalar_from_bytes32(&payload.accounts_root_hash.unwrap()).unwrap(),
            utils::parse_pallas_scalar(
                "0x2d79ad7ee66416fc6ddaabd61a1a2d597852c655652ded77128a651f1f0966b4"
            )
        );
        assert_eq!(
            proto::pallas_scalar_from_bytes32(&payload.program_storage_root_hash.unwrap()).unwrap(),
            utils::parse_pallas_scalar(
                "0x297401934d5cc4d84e639092ccb6f336faae9fc1c54cd4e23ef2561f8c63f683"
            )
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_latest_block_at_genesis() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;

        let response = client
            .get_block(dotakon::GetBlockRequest { block_hash: None })
            .await
            .unwrap();
        let response = response.get_ref();
        let payload = response.payload.as_ref().unwrap();
        assert!(
            keys::KeyManager::verify_signed_message(
                &payload,
                &response.signature.as_ref().unwrap()
            )
            .is_ok()
        );
        let payload = payload.to_msg::<dotakon::BlockDescriptor>().unwrap();

        assert_eq!(
            proto::pallas_scalar_from_bytes32(&payload.block_hash.unwrap()).unwrap(),
            default_genesis_block_hash()
        );
        assert_eq!(payload.block_number.unwrap(), 0);
        assert_eq!(
            proto::pallas_scalar_from_bytes32(&payload.previous_block_hash.unwrap()).unwrap(),
            Scalar::ZERO
        );
        assert_eq!(
            proto::pallas_scalar_from_bytes32(&payload.network_topology_root_hash.unwrap())
                .unwrap(),
            utils::parse_pallas_scalar(
                "0x3f75bfd1de06f77cce4d43d38ffac77eac6a8de697cf3b2a798bc19f1cb1c2b2"
            )
        );
        assert_eq!(
            proto::pallas_scalar_from_bytes32(&payload.accounts_root_hash.unwrap()).unwrap(),
            utils::parse_pallas_scalar(
                "0x2d79ad7ee66416fc6ddaabd61a1a2d597852c655652ded77128a651f1f0966b4"
            )
        );
        assert_eq!(
            proto::pallas_scalar_from_bytes32(&payload.program_storage_root_hash.unwrap()).unwrap(),
            utils::parse_pallas_scalar(
                "0x297401934d5cc4d84e639092ccb6f336faae9fc1c54cd4e23ef2561f8c63f683"
            )
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_unknown_block() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;
        assert!(
            client
                .get_block(dotakon::GetBlockRequest {
                    block_hash: Some(proto::pallas_scalar_to_bytes32(utils::parse_pallas_scalar(
                        "0x375830d6862157562431f637dcb4aa91e2bba7220abfa58b7618a713e9bb8803"
                    ))),
                })
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_default_initial_account_balance() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;

        let (_, public_key, _) = utils::testing_keys3();
        let account_address = utils::public_key_to_wallet_address(public_key);

        let response = client
            .get_account(dotakon::GetAccountRequest {
                account_address: Some(proto::pallas_scalar_to_bytes32(account_address)),
                block_hash: Some(proto::pallas_scalar_to_bytes32(default_genesis_block_hash())),
            })
            .await
            .unwrap();
        let response = response.get_ref();
        let payload = response.payload.as_ref().unwrap();
        assert!(
            keys::KeyManager::verify_signed_message(
                &payload,
                &response.signature.as_ref().unwrap()
            )
            .is_ok()
        );
        let payload = payload.to_msg::<dotakon::MerkleProof>().unwrap();

        let block_info = db::BlockInfo::decode(&payload.block_descriptor.unwrap()).unwrap();
        assert_eq!(block_info.hash(), default_genesis_block_hash());

        let proof =
            tree::AccountProof::decode_and_verify(&payload, block_info.accounts_root_hash())
                .unwrap();
        assert_eq!(proof.key(), account_address);
        assert_eq!(*proof.value(), AccountInfo::with_balance(Scalar::ZERO));
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_latest_account_balance_at_genesis() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;

        let (_, public_key, _) = utils::testing_keys3();
        let account_address = utils::public_key_to_wallet_address(public_key);

        let response = client
            .get_account(dotakon::GetAccountRequest {
                account_address: Some(proto::pallas_scalar_to_bytes32(account_address)),
                block_hash: None,
            })
            .await
            .unwrap();
        let response = response.get_ref();
        let payload = response.payload.as_ref().unwrap();
        assert!(
            keys::KeyManager::verify_signed_message(
                &payload,
                &response.signature.as_ref().unwrap()
            )
            .is_ok()
        );
        let payload = payload.to_msg::<dotakon::MerkleProof>().unwrap();

        let block_info = db::BlockInfo::decode(&payload.block_descriptor.unwrap()).unwrap();
        assert_eq!(block_info.hash(), default_genesis_block_hash());

        let proof =
            tree::AccountProof::decode_and_verify(&payload, block_info.accounts_root_hash())
                .unwrap();
        assert_eq!(proof.key(), account_address);
        assert_eq!(*proof.value(), AccountInfo::with_balance(Scalar::ZERO));
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_initial_account_state() {
        let (_, public_key, _) = utils::testing_keys3();
        let account_address = utils::public_key_to_wallet_address(public_key);

        let mut fixture =
            TestFixture::with_initial_balances([(account_address, Scalar::from(123))])
                .await
                .unwrap();
        let client = &mut fixture.client;

        let response = client
            .get_account(dotakon::GetAccountRequest {
                account_address: Some(proto::pallas_scalar_to_bytes32(account_address)),
                block_hash: None,
            })
            .await
            .unwrap();
        let response = response.get_ref();
        let payload = response.payload.as_ref().unwrap();
        assert!(
            keys::KeyManager::verify_signed_message(
                &payload,
                &response.signature.as_ref().unwrap()
            )
            .is_ok()
        );
        let payload = payload.to_msg::<dotakon::MerkleProof>().unwrap();

        let block_info = db::BlockInfo::decode(&payload.block_descriptor.unwrap()).unwrap();
        assert_eq!(
            block_info.hash(),
            utils::parse_pallas_scalar(
                "0x2ec1d893da43bd4c60f0bfe5ed512cfb5c586a75bf2fb4a8c125ab001a7a5693"
            )
        );

        let proof =
            tree::AccountProof::decode_and_verify(&payload, block_info.accounts_root_hash())
                .unwrap();
        assert_eq!(proof.key(), account_address);
        assert_eq!(*proof.value(), AccountInfo::with_balance(123.into()));
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_invalid_account_balance1() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;
        assert!(
            client
                .get_account(dotakon::GetAccountRequest {
                    account_address: None,
                    block_hash: Some(proto::pallas_scalar_to_bytes32(default_genesis_block_hash())),
                })
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_invalid_account_balance2() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;
        assert!(
            client
                .get_account(dotakon::GetAccountRequest {
                    account_address: None,
                    block_hash: None,
                })
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_invalid_transaction_lookup() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;
        assert!(
            client
                .get_transaction(dotakon::GetTransactionRequest {
                    transaction_hash: None,
                })
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_unknown_transaction() {
        let mut fixture = TestFixture::default().await.unwrap();
        let client = &mut fixture.client;
        assert!(
            client
                .get_transaction(dotakon::GetTransactionRequest {
                    transaction_hash: Some(proto::h256_to_bytes32(H256::zero())),
                })
                .await
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_block_closure() {
        let mut fixture = TestFixture::default().await.unwrap();

        let response = fixture
            .client
            .get_block(dotakon::GetBlockRequest { block_hash: None })
            .await
            .unwrap();
        let response = response.get_ref();
        let payload = response.payload.as_ref().unwrap();
        assert!(
            keys::KeyManager::verify_signed_message(
                &payload,
                &response.signature.as_ref().unwrap()
            )
            .is_ok()
        );
        let payload = &payload.to_msg::<dotakon::BlockDescriptor>().unwrap();
        assert_eq!(payload.block_number.unwrap(), 0);
        assert_eq!(
            proto::pallas_scalar_from_bytes32(&payload.block_hash.unwrap()).unwrap(),
            default_genesis_block_hash()
        );

        fixture.clock().advance(Duration::from_secs(10)).await;
        yield_now().await;

        let response = fixture
            .client
            .get_block(dotakon::GetBlockRequest { block_hash: None })
            .await
            .unwrap();
        let response = response.get_ref();
        let payload = response.payload.as_ref().unwrap();
        assert!(
            keys::KeyManager::verify_signed_message(
                &payload,
                &response.signature.as_ref().unwrap()
            )
            .is_ok()
        );
        let payload = &payload.to_msg::<dotakon::BlockDescriptor>().unwrap();
        assert_eq!(payload.block_number.unwrap(), 1);
        assert_eq!(
            proto::pallas_scalar_from_bytes32(&payload.block_hash.unwrap()).unwrap(),
            utils::parse_pallas_scalar(
                "0x0c30e58b065d0a9791504ca7e8d7c4e03207145534b79f05e7f5374e97afff30"
            )
        );
    }
}
