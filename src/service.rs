use crate::dotakon::{self, node_service_v1_server::NodeServiceV1};
use crate::proto;
use crate::utils;
use crate::{keys, net};
use anyhow::{Context, Result};
use primitive_types::U256;
use rand_core::{OsRng, RngCore};
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

fn get_random() -> U256 {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    U256::from_little_endian(&bytes)
}

#[derive(Debug)]
pub struct NodeService {
    key_manager: Arc<keys::KeyManager>,
    identity: dotakon::node_identity::Payload,
}

impl NodeService {
    fn get_protocol_version() -> dotakon::ProtocolVersion {
        dotakon::ProtocolVersion {
            major: Some(1),
            minor: Some(0),
            build: Some(0),
        }
    }

    fn make_node_identity(
        key_manager: &keys::KeyManager,
        location: dotakon::GeographicalLocation,
        public_address: &str,
        port: u16,
    ) -> dotakon::node_identity::Payload {
        dotakon::node_identity::Payload {
            protocol_version: Some(Self::get_protocol_version()),
            wallet_address: Some(proto::encode_bytes32(key_manager.wallet_address())),
            location: Some(location),
            network_address: Some(public_address.to_owned()),
            grpc_port: Some(port.into()),
            http_port: None,
            timestamp: Some(prost_types::Timestamp {
                seconds: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
                nanos: 0,
            }),
        }
    }

    pub fn new(
        key_manager: Arc<keys::KeyManager>,
        location: dotakon::GeographicalLocation,
        public_address: &str,
        port: u16,
    ) -> Self {
        println!("Public key: {:#x}", key_manager.public_key());
        println!(
            "Public key (Ed25519): {:#x}",
            key_manager.public_key_25519()
        );
        println!(
            "Wallet address: {}",
            utils::format_wallet_address(key_manager.wallet_address())
        );
        let identity = Self::make_node_identity(&*key_manager, location, public_address, port);
        Self {
            key_manager,
            identity,
        }
    }

    fn get_client_public_key<M>(&self, request: &Request<M>) -> Result<U256> {
        let info = request
            .extensions()
            .get::<net::ConnectionInfo>()
            .context("certificate not found")?;
        Ok(info.peer_public_key())
    }

    fn get_client_wallet_address<M>(&self, request: &Request<M>) -> Result<U256> {
        let info = request
            .extensions()
            .get::<net::ConnectionInfo>()
            .context("certificate not found")?;
        Ok(info.peer_wallet_address())
    }

    fn sign_message<M: prost::Message + prost::Name>(
        &self,
        message: &M,
    ) -> Result<dotakon::Signature> {
        self.key_manager.sign_message(message, get_random())
    }

    fn verify_signed_message<M: prost::Message + prost::Name>(
        message: &M,
        signature: &dotakon::Signature,
    ) -> Result<()> {
        keys::KeyManager::verify_signed_message(message, signature)
    }
}

#[tonic::async_trait]
impl NodeServiceV1 for NodeService {
    async fn get_identity(
        &self,
        _request: Request<dotakon::GetIdentityRequest>,
    ) -> Result<Response<dotakon::NodeIdentity>, Status> {
        let payload = prost_types::Any::from_msg(&self.identity)
            .map_err(|_| Status::internal("protobuf encoding error"))?;
        let signature = self
            .sign_message(&self.identity)
            .map_err(|_| Status::internal("signature error"))?;
        Ok(Response::new(dotakon::NodeIdentity {
            payload: Some(payload),
            signature: Some(signature),
        }))
    }

    async fn get_topology(
        &self,
        _request: Request<dotakon::GetTopologyRequest>,
    ) -> Result<Response<dotakon::NetworkTopology>, Status> {
        todo!()
    }

    async fn get_account_balance(
        &self,
        _request: Request<dotakon::GetAccountBalanceRequest>,
    ) -> Result<Response<dotakon::GetAccountBalanceResponse>, Status> {
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
    use crate::dotakon::{
        self, node_service_v1_client::NodeServiceV1Client,
        node_service_v1_server::NodeServiceV1Server,
    };
    use crate::ssl;
    use tokio::sync::Notify;
    use tonic::transport::Server;

    #[tokio::test]
    async fn test_identity() {
        let nonce = U256::from_little_endian(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 0, 0,
        ]);

        let (server_secret_key, server_public_key, _) = utils::testing_keys1();
        let server_key_manager = Arc::new(keys::KeyManager::new(server_secret_key).unwrap());
        let server_certificate = Arc::new(
            ssl::generate_certificate(server_key_manager.clone(), "server".to_string(), nonce)
                .unwrap(),
        );

        let (client_secret_key, _, _) = utils::testing_keys2();
        let client_key_manager = Arc::new(keys::KeyManager::new(client_secret_key).unwrap());
        let client_certificate = Arc::new(
            ssl::generate_certificate(client_key_manager.clone(), "client".to_string(), nonce)
                .unwrap(),
        );

        let service = NodeServiceV1Server::new(NodeService::new(
            server_key_manager.clone(),
            dotakon::GeographicalLocation {
                latitude: Some(71),
                longitude: Some(104),
            },
            "localhost",
            8081,
        ));

        let server_ready = Arc::new(Notify::new());
        let start_client = server_ready.clone();
        let server = tokio::task::spawn(async move {
            let future = Server::builder().add_service(service).serve_with_incoming(
                net::IncomingWithMTls::new(
                    "localhost:8081",
                    server_key_manager,
                    server_certificate,
                )
                .await
                .unwrap(),
            );
            server_ready.notify_one();
            future.await.unwrap();
        });
        start_client.notified().await;

        let (channel, _) = net::connect_with_mtls(
            client_key_manager.clone(),
            client_certificate.clone(),
            "http://localhost:8081".parse().unwrap(),
        )
        .await
        .unwrap();
        let mut client = NodeServiceV1Client::new(channel);

        let response = client
            .get_identity(dotakon::GetIdentityRequest::default())
            .await
            .unwrap();
        let identity = response.get_ref();
        let payload = identity
            .payload
            .as_ref()
            .unwrap()
            .to_msg::<dotakon::node_identity::Payload>()
            .unwrap();
        assert!(
            keys::KeyManager::verify_signed_message(
                &payload,
                &identity.signature.as_ref().unwrap()
            )
            .is_ok()
        );

        server.abort();
    }

    // TODO
}
