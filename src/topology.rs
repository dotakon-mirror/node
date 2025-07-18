use crate::{dotakon, proto};
use anyhow::{Context, Result, anyhow};
use primitive_types::H256;
use sha3::{self, Digest};
use std::collections::BTreeSet;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Location {
    pub latitude: i32,
    pub longitude: u32,
}

#[derive(Debug, Clone)]
pub struct Node {
    account_address: H256,
    signed_identity: dotakon::NodeIdentity,
    location: Location,
    network_address: String,
    grpc_port: u16,
    http_port: u16,
}

impl Node {
    fn sanitize_port_number(port: u32) -> Result<u16> {
        if port > 0xFFFF {
            Err(anyhow!("invalid port number: {}", port))
        } else {
            Ok(port as u16)
        }
    }

    pub fn new(identity: dotakon::NodeIdentity) -> Result<Self> {
        let payload = &identity
            .payload
            .as_ref()
            .context("payload missing")?
            .to_msg::<dotakon::node_identity::Payload>()?;
        let account_address = proto::h256_from_bytes32(
            &payload
                .account_address
                .context("account address field missing")?,
        );
        let location = payload
            .location
            .context("geographical location field missing")?;
        let latitude = location.latitude.context("latitude field missing")?;
        let longitude = location.longitude.context("longitude field missing")?;
        let network_address = payload
            .network_address
            .as_ref()
            .context("network address field missing")?
            .clone();
        let grpc_port =
            Self::sanitize_port_number(payload.grpc_port.context("gRPC port field missing")?)?;
        let http_port =
            Self::sanitize_port_number(payload.http_port.context("HTTP port field missing")?)?;
        Ok(Self {
            account_address,
            signed_identity: identity,
            location: Location {
                latitude,
                longitude,
            },
            network_address,
            grpc_port,
            http_port,
        })
    }

    pub fn account_address(&self) -> H256 {
        self.account_address
    }

    pub fn hash(&self) -> H256 {
        self.account_address
    }

    pub fn signed_identity(&self) -> &dotakon::NodeIdentity {
        &self.signed_identity
    }

    pub fn location(&self) -> &Location {
        &self.location
    }

    pub fn network_address(&self) -> &str {
        self.network_address.as_str()
    }

    pub fn grpc_port(&self) -> u16 {
        self.grpc_port
    }

    pub fn http_port(&self) -> u16 {
        self.http_port
    }
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.account_address == other.account_address
    }
}

impl Eq for Node {}

impl PartialOrd for Node {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Node {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.account_address.cmp(&other.account_address)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cluster {
    nodes: Vec<Node>,
    hash: H256,
}

impl Cluster {
    fn hash_nodes(nodes: &[Node]) -> H256 {
        const DOMAIN_SEPARATOR: &str = "dotakon/topology-hash-v1/cluster";
        let node_hashes: Vec<String> = nodes
            .iter()
            .map(|node| format!("{:#x}", node.hash()))
            .collect();
        let message = format!(
            "{{domain=\"{}\",nodes=[{}]}}",
            DOMAIN_SEPARATOR,
            node_hashes.join(",")
        );
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(message.as_bytes());
        H256::from_slice(hasher.finalize().as_slice())
    }

    fn from<const N: usize>(nodes: [Node; N]) -> Result<Self> {
        let node_set =
            BTreeSet::from_iter(nodes.as_ref().iter().map(|node| node.account_address()));
        if node_set.len() < N {
            return Err(anyhow!("two or more nodes have the same account address"));
        }
        let hash = Self::hash_nodes(nodes.as_slice());
        Ok(Self {
            nodes: Vec::from(nodes),
            hash,
        })
    }

    pub fn hash(&self) -> H256 {
        self.hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    clusters: Vec<Cluster>,
    hash: H256,
}

impl Network {
    fn hash_network(clusters: &[Cluster]) -> H256 {
        const DOMAIN_SEPARATOR: &str = "dotakon/topology-hash-v1/network";
        let cluster_hashes: Vec<String> = clusters
            .iter()
            .map(|cluster| format!("{:#x}", cluster.hash()))
            .collect();
        let message = format!(
            "{{domain=\"{}\",clusters=[{}]}}",
            DOMAIN_SEPARATOR,
            cluster_hashes.join(",")
        );
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(message.as_bytes());
        H256::from_slice(hasher.finalize().as_slice())
    }

    pub fn new(identity: dotakon::NodeIdentity) -> Result<Self> {
        let clusters = vec![Cluster::from([Node::new(identity)?])?];
        let hash = Self::hash_network(clusters.as_slice());
        Ok(Self { clusters, hash })
    }

    pub fn root_hash(&self) -> H256 {
        self.hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;
    use crate::utils;

    #[test]
    fn test_node() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = keys::KeyManager::new(secret_key);
        let identity = dotakon::node_identity::Payload {
            protocol_version: Some(dotakon::ProtocolVersion {
                major: Some(1),
                minor: Some(0),
                build: Some(0),
            }),
            account_address: Some(proto::h256_to_bytes32(key_manager.wallet_address())),
            location: Some(dotakon::GeographicalLocation {
                latitude: Some(71),
                longitude: Some(104),
            }),
            network_address: Some("localhost".to_string()),
            grpc_port: Some(4443),
            http_port: Some(8080),
            timestamp: Some(prost_types::Timestamp::date(2009, 1, 3).unwrap()),
        };
        let (payload, signature) = key_manager
            .sign_message(
                &identity,
                H256::from_slice(&[
                    1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
                ]),
            )
            .unwrap();
        let identity = dotakon::NodeIdentity {
            payload: Some(payload),
            signature: Some(signature),
        };
        let node = Node::new(identity.clone()).unwrap();
        assert_eq!(node.account_address(), key_manager.wallet_address());
        assert_eq!(node.hash(), key_manager.wallet_address());
        assert_eq!(*node.signed_identity(), identity);
        assert_eq!(node.location().latitude, 71);
        assert_eq!(node.location().longitude, 104);
        assert_eq!(node.network_address(), "localhost");
        assert_eq!(node.grpc_port(), 4443);
        assert_eq!(node.http_port(), 8080);
    }

    // TODO
}
