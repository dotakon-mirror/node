use anyhow::Result;
use dotakon::node_service_v1_server::NodeServiceV1;
use std::pin::Pin;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

use crate::dotakon;
use crate::keys;

#[derive(Debug)]
pub struct NodeService {
    key_manager: keys::KeyManager,
}

impl NodeService {
    pub fn new(key_manager: keys::KeyManager) -> Self {
        println!("Public key: {:#x}", key_manager.public_key());
        println!(
            "Public key (Ed25519): {:#x}",
            key_manager.public_key_25519()
        );
        println!("Wallet address: {:#x}", key_manager.wallet_address());
        NodeService { key_manager }
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
