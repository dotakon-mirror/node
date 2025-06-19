use std::pin::Pin;

use anyhow::Result;
use clap::Parser;
use dotakon::node_service_v1_server::{NodeServiceV1, NodeServiceV1Server};
use pasta_curves::group::{Group, GroupEncoding};
use pasta_curves::pallas;
use primitive_types::U256;
use sha3::{Digest, Sha3_256};
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming, transport::Server};

mod utils;

pub mod dotakon {
    tonic::include_proto!("dotakon");
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The private key of the wallet used to stake DOT and receive rewards.
    #[arg(long)]
    private_key: String,

    /// The canonical address of this node. It may be an IPv4 address, an IPv6 address, or a DNS
    /// address. The gRPC server must be reachable at this address at all times.
    #[arg(long)]
    public_address: String,

    /// The local IP address the gRPC service binds to. If unspecified the service will bind to all
    /// available network interfaces.
    #[arg(long, default_value = "[::]")]
    local_address: String,

    /// The TCP port where the gRPC service is exposed.
    #[arg(long)]
    port: u16,

    /// The latitude of the self-declared geographical location of the node.
    #[arg(long)]
    latitude: u64,

    /// The longitude of the self-declared geographical location of the node.
    #[arg(long)]
    longitude: u64,
}

#[derive(Debug, Default)]
struct NodeService {}

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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let private_key_u256 = U256::from_str_radix(args.private_key.as_str(), 16)?;
    let private_key = utils::u256_to_pallas_scalar(private_key_u256)?;

    let public_key_point = pallas::Point::generator() * private_key;
    let public_key = U256::from_little_endian(&public_key_point.to_bytes());

    let mut hasher = Sha3_256::new();
    hasher.update(public_key.to_little_endian());
    let address = hasher.finalize();

    println!("Private key: {:#x}", private_key_u256);
    println!("Public key: {:#x}", public_key);
    println!("Wallet address: 0x{:#x}", address);

    let local_address = format!("{}:{}", args.local_address, args.port);
    println!("listening on {}", local_address);

    Server::builder()
        .add_service(NodeServiceV1Server::new(NodeService::default()))
        .serve(local_address.parse()?)
        .await?;

    Ok(())
}
