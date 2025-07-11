use crate::dotakon::{self, node_service_v1_server::NodeServiceV1};
use std::pin::Pin;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

#[cfg(test)]
pub struct FakeNodeService {}

#[cfg(test)]
#[tonic::async_trait]
impl NodeServiceV1 for FakeNodeService {
    async fn get_identity(
        &self,
        _request: Request<dotakon::GetIdentityRequest>,
    ) -> Result<Response<dotakon::NodeIdentity>, Status> {
        Ok(Response::new(dotakon::NodeIdentity {
            payload: None,
            signature: None,
        }))
    }

    async fn get_block(
        &self,
        _request: Request<dotakon::GetBlockRequest>,
    ) -> Result<Response<dotakon::GetBlockResponse>, Status> {
        Ok(Response::new(dotakon::GetBlockResponse {
            payload: None,
            signature: None,
        }))
    }

    async fn get_topology(
        &self,
        _request: Request<dotakon::GetTopologyRequest>,
    ) -> Result<Response<dotakon::NetworkTopology>, Status> {
        Ok(Response::new(dotakon::NetworkTopology { cluster: vec![] }))
    }

    async fn get_account_balance(
        &self,
        _request: Request<dotakon::GetAccountBalanceRequest>,
    ) -> Result<Response<dotakon::GetAccountBalanceResponse>, Status> {
        Ok(Response::new(dotakon::GetAccountBalanceResponse {
            payload: None,
            signature: None,
        }))
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
