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

    fn sign_message(&self, message: &prost_types::Any) -> Result<dotakon::Signature> {
        self.key_manager.sign_message(message, get_random())
    }

    fn verify_signed_message(
        message: &prost_types::Any,
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
            .sign_message(&payload)
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
    // TODO
}
