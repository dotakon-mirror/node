use crate::dotakon::{self, node_service_v1_server::NodeServiceV1};
use crate::utils;
use crate::{keys, net};
use anyhow::{Context, Result};
use primitive_types::U256;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

#[derive(Debug)]
pub struct NodeService {
    key_manager: Arc<keys::KeyManager>,
}

impl NodeService {
    pub fn new(key_manager: Arc<keys::KeyManager>) -> Self {
        println!("Public key: {:#x}", key_manager.public_key());
        println!(
            "Public key (Ed25519): {:#x}",
            key_manager.public_key_25519()
        );
        println!(
            "Wallet address: {}",
            utils::format_wallet_address(key_manager.wallet_address())
        );
        Self { key_manager }
    }

    fn get_peer_public_key<M>(&self, request: &Request<M>) -> Result<U256> {
        let info = request
            .extensions()
            .get::<net::ConnectionInfo>()
            .context("certificate not found")?;
        Ok(info.peer_public_key())
    }

    fn get_peer_wallet_address<M>(&self, request: &Request<M>) -> Result<U256> {
        let info = request
            .extensions()
            .get::<net::ConnectionInfo>()
            .context("certificate not found")?;
        Ok(info.peer_wallet_address())
    }
}

#[tonic::async_trait]
impl NodeServiceV1 for NodeService {
    async fn get_identity(
        &self,
        _request: Request<dotakon::GetIdentityRequest>,
    ) -> Result<Response<dotakon::NodeIdentity>, Status> {
        todo!()
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
