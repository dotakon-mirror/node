use anyhow::Result;
use dotakon::node_service_v1_server::NodeServiceV1;
use pasta_curves::{
    group::{Group, GroupEncoding},
    pallas,
};
use primitive_types::U256;
use sha3::{Digest, Sha3_256};
use std::pin::Pin;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

use crate::dotakon;
use crate::utils;

#[derive(Debug)]
pub struct NodeService {
    private_key: pallas::Scalar,
    pub public_key_point: pallas::Point,
    pub public_key: U256,
    pub wallet_address: U256,
}

impl NodeService {
    pub fn new(private_key: pallas::Scalar) -> Self {
        let public_key_point = pallas::Point::generator() * private_key;
        let public_key = U256::from_little_endian(&public_key_point.to_bytes());

        let mut hasher = Sha3_256::new();
        hasher.update(public_key.to_little_endian());
        let wallet_address = U256::from_big_endian(hasher.finalize().as_slice());

        println!(
            "Private key: {:#x}",
            utils::pallas_scalar_to_u256(private_key)
        );
        println!("Public key: {:#x}", public_key);
        println!("Wallet address: {:#x}", wallet_address);

        NodeService {
            private_key,
            public_key_point,
            public_key,
            wallet_address,
        }
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
