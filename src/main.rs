use anyhow::Result;
use clap::Parser;
use dotakon::node_service_v1_server::NodeServiceV1Server;
use primitive_types::U256;
use rand_core::{OsRng, RngCore};
use tonic::transport::Server;

mod keys;
mod service;
mod ssl;
mod utils;

pub mod dotakon {
    tonic::include_proto!("dotakon");
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The private key of the wallet used to stake DOT and receive rewards. If this is left empty
    /// the node will generate a new key securely at startup, but the corresponding Dotakon account
    /// will be empty and so the node won't be able to join an existing network, it will have to
    /// start a new one.
    #[arg(long, default_value = "")]
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

    let private_key = if args.private_key.is_empty() {
        let mut bytes = [0u8; 32];
        OsRng.try_fill_bytes(&mut bytes)?;
        bytes[31] &= 0x0F;
        let key = U256::from_little_endian(&bytes);
        println!("New private key: {:#x}", key);
        key
    } else {
        U256::from_str_radix(args.private_key.as_str(), 16)?
    };

    let key_manager = keys::KeyManager::new(private_key)?;
    let server = Server::builder().add_service(NodeServiceV1Server::new(
        service::NodeService::new(key_manager),
    ));

    let local_address = format!("{}:{}", args.local_address, args.port);
    println!("listening on {}", local_address);

    server.serve(local_address.parse()?).await?;

    Ok(())
}
