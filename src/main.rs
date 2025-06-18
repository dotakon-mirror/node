use ff::Field;
use pasta_curves::group::{Group, GroupEncoding};
use pasta_curves::pallas;
use rand_core::OsRng;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The canonical address of this node. It may be an IPv4 address, an IPv6 address, or a DNS
    /// address. The gRPC server must be reachable at this address at all times.
    #[arg(long)]
    address: String,

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

#[tokio::main]
async fn main() {
    let args = Args::parse();
    dbg!(args);

    // Generate random scalar (private key)
    let sk = pallas::Scalar::random(&mut OsRng);

    // Compute public key: PK = sk * G
    let pk = pallas::Point::generator() * sk;

    println!("Private key (scalar): {:?}", sk);
    println!("Public key (point): {:?}", pk.to_bytes());
}
