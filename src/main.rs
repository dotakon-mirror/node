use anyhow::Result;
use clap::Parser;
use dotakon::node_service_v1_server::NodeServiceV1Server;
use primitive_types::U256;
use tonic::transport::Server;

mod service;
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

    /// A list of well-known nodes to connect to in order to join an existing network. If the list
    /// is left empty this node will start a new network.
    #[arg(long, default_value = "")]
    bootstrap_list: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let private_key_u256 = U256::from_str_radix(args.private_key.as_str(), 16)?;
    let private_key = utils::u256_to_pallas_scalar(private_key_u256)?;

    let server = Server::builder().add_service(NodeServiceV1Server::new(
        service::NodeService::new(private_key),
    ));

    let local_address = format!("{}:{}", args.local_address, args.port);
    println!("listening on {}", local_address);

    server.serve(local_address.parse()?).await?;

    Ok(())
}
