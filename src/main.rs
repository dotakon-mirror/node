use anyhow::Result;
use clap::Parser;
use dotakon::node_service_v1_server::NodeServiceV1Server;
use primitive_types::U256;
use rand_core::{OsRng, RngCore};
use std::sync::Arc;
use tonic::transport::Server;

mod keys;
mod net;
mod service;
mod ssl;
mod utils;

#[cfg(test)]
mod fake;

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
    secret_key: String,

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

fn get_random() -> U256 {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    U256::from_little_endian(&bytes)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let secret_key = if args.secret_key.is_empty() {
        let key = get_random();
        println!("New secret key: {:#x}", key);
        key
    } else {
        U256::from_str_radix(args.secret_key.as_str(), 16)?
    };

    let key_manager = Arc::new(keys::KeyManager::new(secret_key)?);
    let certificate = Arc::new(ssl::generate_certificate(
        key_manager.clone(),
        args.public_address,
        /*nonce=*/ get_random(),
    )?);

    let server = Server::builder().add_service(NodeServiceV1Server::new(
        service::NodeService::new(key_manager.clone()),
    ));

    let local_address = format!("{}:{}", args.local_address, args.port);
    println!("listening on {}", local_address);

    server
        .serve_with_incoming(
            net::IncomingWithMTls::new(local_address, key_manager, certificate).await?,
        )
        .await?;

    Ok(())
}
