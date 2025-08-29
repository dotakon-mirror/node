use crate::dotakon;
use crate::proto;
use crate::utils;
use anyhow::{Context, Result, anyhow};
use pasta_curves::pallas::Scalar;
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
    account_address: Scalar,
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
        let account_address = proto::pallas_scalar_from_bytes32(
            &payload
                .account_address
                .context("account address field missing")?,
        )?;
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

    pub fn account_address(&self) -> Scalar {
        self.account_address
    }

    pub fn hash(&self) -> Scalar {
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
struct Clique {
    nodes: Vec<Node>,
    hash: H256,
}

impl Clique {
    fn hash_nodes(nodes: &[Node]) -> H256 {
        const DOMAIN_SEPARATOR: &str = "dotakon/topology-hash-v1/clique";
        let node_hashes: Vec<String> = nodes
            .iter()
            .map(|node| format!("{:#x}", utils::pallas_scalar_to_u256(node.hash())))
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

    pub fn node(&self, index: usize) -> &Node {
        &self.nodes[index]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    cliques: Vec<Clique>,
    own_clique_index: usize,
    own_node_index: usize,
    hash: Scalar,
}

impl Network {
    fn hash_network(cliques: &[Clique]) -> Scalar {
        const DOMAIN_SEPARATOR: &str = "dotakon/topology-hash-v1/network";
        let clique_hashes: Vec<String> = cliques
            .iter()
            .map(|clique| format!("{:#x}", clique.hash()))
            .collect();
        let message = format!(
            "{{domain=\"{}\",cliques=[{}]}}",
            DOMAIN_SEPARATOR,
            clique_hashes.join(",")
        );
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(message.as_bytes());
        utils::hash_to_pallas_scalar(H256::from_slice(hasher.finalize().as_slice()))
    }

    pub fn new(identity: dotakon::NodeIdentity) -> Result<Self> {
        let cliques = vec![Clique::from([Node::new(identity)?])?];
        let hash = Self::hash_network(cliques.as_slice());
        Ok(Self {
            cliques,
            own_clique_index: 0,
            own_node_index: 0,
            hash,
        })
    }

    pub fn root_hash(&self) -> Scalar {
        self.hash
    }

    pub fn get_self(&self) -> &Node {
        self.cliques[self.own_clique_index].node(self.own_node_index)
    }

    pub async fn broadcast_transaction(&self, transaction: &dotakon::Transaction) -> Result<()> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;
    use crate::utils;
    use primitive_types::H256;

    fn testing_identity() -> (keys::KeyManager, dotakon::NodeIdentity) {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = keys::KeyManager::new(secret_key);
        let identity = dotakon::node_identity::Payload {
            protocol_version: Some(dotakon::ProtocolVersion {
                major: Some(1),
                minor: Some(0),
                build: Some(0),
            }),
            account_address: Some(proto::pallas_scalar_to_bytes32(
                key_manager.wallet_address(),
            )),
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
        (
            key_manager,
            dotakon::NodeIdentity {
                payload: Some(payload),
                signature: Some(signature),
            },
        )
    }

    #[test]
    fn test_node() {
        let (key_manager, identity) = testing_identity();
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

    #[test]
    fn test_new_network() {
        let (key_manager, identity) = testing_identity();
        let network = Network::new(identity).unwrap();
        assert_eq!(network.own_clique_index, 0);
        assert_eq!(network.own_node_index, 0);
        assert_eq!(
            network.root_hash(),
            utils::parse_pallas_scalar(
                "0x3f75bfd1de06f77cce4d43d38ffac77eac6a8de697cf3b2a798bc19f1cb1c2b2"
            )
        );
        let node = network.get_self();
        assert_eq!(node.account_address(), key_manager.wallet_address());
        assert_eq!(node.hash(), key_manager.wallet_address());
    }

    // TODO
}
