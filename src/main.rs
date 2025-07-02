use anyhow::{Result, anyhow};
use clap::Parser;
use dotakon::node_service_v1_server::NodeServiceV1Server;
use primitive_types::U256;
use rand_core::{OsRng, RngCore};
use std::fs::File;
use std::sync::Arc;
use tonic::transport::Server;

mod db;
mod keys;
mod net;
mod proto;
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

    /// The latitude of the self-declared geographical location of the node, expressed in degrees
    /// between -90.0 and +90.0.
    #[arg(long)]
    latitude: f64,

    /// The longitude of the self-declared geographical location of the node, expressed in degrees
    /// between 0.0 and 180.0.
    #[arg(long)]
    longitude: f64,

    /// A list of well-known nodes to connect to in order to join an existing network. If the list
    /// is left empty this node will start a new network.
    #[arg(long, default_value = "")]
    bootstrap_list: Vec<String>,

    /// Path of the file where the blockchain data is stored.
    #[arg(long)]
    db_path: String,
}

fn get_random() -> U256 {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    U256::from_little_endian(&bytes)
}

fn make_location(latitude: f64, longitude: f64) -> Result<dotakon::GeographicalLocation> {
    if latitude < -90.0 || latitude > 90.0 {
        return Err(anyhow!("the latitude is out of range"));
    }
    if longitude < 0.0 || longitude > 180.0 {
        return Err(anyhow!("the longitude is out of range"));
    }
    Ok(dotakon::GeographicalLocation {
        latitude: Some((latitude * 60.0) as i32),
        longitude: Some((longitude * 60.0) as u32),
    })
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

    let key_manager = Arc::new(keys::KeyManager::new(secret_key));
    let certificate = Arc::new(ssl::generate_certificate(
        key_manager.clone(),
        args.public_address.clone(),
        /*nonce=*/ get_random(),
    )?);

    let location = make_location(args.latitude, args.longitude)?;
    let data_file = File::open(args.db_path)?;
    let server =
        Server::builder().add_service(NodeServiceV1Server::new(service::NodeService::new(
            key_manager.clone(),
            location,
            args.public_address.as_str(),
            args.port,
            data_file,
        )));

    let local_address = format!("{}:{}", args.local_address, args.port);
    println!("listening on {}", local_address);

    server
        .serve_with_incoming(
            net::IncomingWithMTls::new(local_address, key_manager, certificate).await?,
        )
        .await?;

    Ok(())
}
