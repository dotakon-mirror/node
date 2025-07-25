use crate::clock::Clock;
use crate::dotakon;
use crate::keys;
use crate::mpt;
use crate::proto;
use crate::topology;
use crate::utils;
use anyhow::{Context, Result, anyhow};
use ff::Field;
use pasta_curves::pallas::Scalar;
use primitive_types::H256;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    hash: Scalar,
    number: u64,
    previous_block_hash: Scalar,
    timestamp: SystemTime,
    network_topology_root_hash: Scalar,
    last_transaction_hash: Scalar,
    account_balances_root_hash: Scalar,
    program_storage_root_hash: Scalar,
}

impl BlockInfo {
    fn hash_block(
        block_number: u64,
        previous_block_hash: Scalar,
        timestamp: SystemTime,
        network_topology_root_hash: Scalar,
        last_transaction_hash: Scalar,
        account_balances_root_hash: Scalar,
        program_storage_root_hash: Scalar,
    ) -> Scalar {
        utils::poseidon_hash([
            Scalar::from(block_number),
            previous_block_hash,
            Scalar::from(
                timestamp
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            network_topology_root_hash,
            last_transaction_hash,
            account_balances_root_hash,
            program_storage_root_hash,
        ])
    }

    fn new(
        block_number: u64,
        previous_block_hash: Scalar,
        timestamp: SystemTime,
        network_topology_root_hash: Scalar,
        last_transaction_hash: Scalar,
        account_balances_root_hash: Scalar,
        program_storage_root_hash: Scalar,
    ) -> Self {
        Self {
            hash: Self::hash_block(
                block_number,
                previous_block_hash,
                timestamp,
                network_topology_root_hash,
                last_transaction_hash,
                account_balances_root_hash,
                program_storage_root_hash,
            ),
            number: block_number,
            previous_block_hash,
            timestamp,
            network_topology_root_hash,
            last_transaction_hash,
            account_balances_root_hash,
            program_storage_root_hash,
        }
    }

    pub fn hash(&self) -> Scalar {
        self.hash
    }

    pub fn number(&self) -> u64 {
        self.number
    }

    pub fn previous_block_hash(&self) -> Scalar {
        self.previous_block_hash
    }

    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    pub fn network_topology_root_hash(&self) -> Scalar {
        self.network_topology_root_hash
    }

    pub fn last_transaction_hash(&self) -> Scalar {
        self.last_transaction_hash
    }

    pub fn account_balances_root_hash(&self) -> Scalar {
        self.account_balances_root_hash
    }

    pub fn program_storage_root_hash(&self) -> Scalar {
        self.program_storage_root_hash
    }

    pub fn encode(&self) -> dotakon::BlockDescriptor {
        dotakon::BlockDescriptor {
            block_hash: Some(proto::pallas_scalar_to_bytes32(self.hash)),
            block_number: Some(self.number),
            previous_block_hash: Some(proto::pallas_scalar_to_bytes32(self.previous_block_hash)),
            timestamp: Some(self.timestamp.into()),
            network_topology_root_hash: Some(proto::pallas_scalar_to_bytes32(
                self.network_topology_root_hash,
            )),
            last_transaction_hash: Some(proto::pallas_scalar_to_bytes32(
                self.last_transaction_hash,
            )),
            account_balances_root_hash: Some(proto::pallas_scalar_to_bytes32(
                self.account_balances_root_hash,
            )),
            program_storage_root_hash: Some(proto::pallas_scalar_to_bytes32(
                self.program_storage_root_hash,
            )),
        }
    }

    pub fn decode(proto: &dotakon::BlockDescriptor) -> Result<BlockInfo> {
        let block_hash = proto::pallas_scalar_from_bytes32(
            &proto.block_hash.context("block hash field is missing")?,
        )?;
        let block_number = proto
            .block_number
            .context("block number field is missing")?;
        let previous_block_hash = proto::pallas_scalar_from_bytes32(
            &proto
                .previous_block_hash
                .context("previous block hash field is missing")?,
        )?;
        let timestamp: SystemTime = proto
            .timestamp
            .context("timestamp field is missing")?
            .try_into()?;
        let network_topology_root_hash = proto::pallas_scalar_from_bytes32(
            &proto
                .network_topology_root_hash
                .context("network topology root hash field is missing")?,
        )?;
        let last_transaction_hash = proto::pallas_scalar_from_bytes32(
            &proto
                .last_transaction_hash
                .context("last transaction hash field is missing")?,
        )?;
        let account_balances_root_hash = proto::pallas_scalar_from_bytes32(
            &proto
                .account_balances_root_hash
                .context("account balance root hash field is missing")?,
        )?;
        let program_storage_root_hash = proto::pallas_scalar_from_bytes32(
            &proto
                .program_storage_root_hash
                .context("program storage root hash field is missing")?,
        )?;
        let block_info = Self::new(
            block_number,
            previous_block_hash,
            timestamp,
            network_topology_root_hash,
            last_transaction_hash,
            account_balances_root_hash,
            program_storage_root_hash,
        );
        if block_hash != block_info.hash {
            Err(anyhow!("block hash mismatch"))
        } else {
            Ok(block_info)
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Transaction {
    parent_hash: Scalar,
    payload: prost_types::Any,
    signature: dotakon::Signature,
    hash: Scalar,
}

impl Transaction {
    fn hash_transfer_coins_transaction(
        parent_hash: Scalar,
        nonce: u64,
        sender_address: Scalar,
        transaction: &dotakon::transaction::TransferCoins,
    ) -> Result<Scalar> {
        Ok(utils::poseidon_hash([
            parent_hash,
            sender_address,
            nonce.into(),
            proto::pallas_scalar_from_bytes32(
                &transaction
                    .recipient
                    .context("invalid coin transfer transaction: recipient field is missing")?,
            )?,
            proto::pallas_scalar_from_bytes32(
                &transaction
                    .amount
                    .context("invalid coin transfer transaction: amount field is missing")?,
            )?,
        ]))
    }

    fn from_proto_impl(
        parent_hash: Scalar,
        payload: prost_types::Any,
        signature: dotakon::Signature,
    ) -> Result<Self> {
        let decoded = payload.to_msg::<dotakon::transaction::Payload>()?;
        let nonce = decoded
            .nonce
            .context("invalid transaction: nonce field is missing")?;
        let signer = proto::pallas_scalar_from_bytes32(
            &signature.signer.context("invalid transaction signature")?,
        )?;
        let hash = match &decoded.transaction.context("invalid transaction")? {
            dotakon::transaction::payload::Transaction::TransferCoins(transaction) => {
                Self::hash_transfer_coins_transaction(parent_hash, nonce, signer, transaction)
            }
            _ => Err(anyhow!("unknown transaction type")),
        }?;
        Ok(Self {
            parent_hash,
            payload,
            signature,
            hash,
        })
    }

    pub fn from_proto(parent_hash: Scalar, proto: dotakon::Transaction) -> Result<Self> {
        let payload = proto.payload.context("invalid transaction")?;
        let signature = proto.signature.context("the transaction is not signed")?;
        Self::from_proto_impl(parent_hash, payload, signature)
    }

    pub fn from_proto_verify(parent_hash: Scalar, proto: dotakon::Transaction) -> Result<Self> {
        let payload = proto.payload.context("invalid transaction")?;
        let signature = proto.signature.context("the transaction is not signed")?;
        keys::KeyManager::verify_signed_message(&payload, &signature)?;
        Self::from_proto_impl(parent_hash, payload, signature)
    }

    pub fn make_coin_transfer_proto(
        key_manager: &keys::KeyManager,
        signature_secret_nonce: H256,
        transaction_nonce: u64,
        recipient_address: Scalar,
        amount: Scalar,
    ) -> Result<dotakon::Transaction> {
        let (payload, signature) = key_manager.sign_message(
            &dotakon::transaction::Payload {
                nonce: Some(transaction_nonce),
                transaction: Some(dotakon::transaction::payload::Transaction::TransferCoins(
                    dotakon::transaction::TransferCoins {
                        recipient: Some(proto::pallas_scalar_to_bytes32(recipient_address)),
                        amount: Some(proto::pallas_scalar_to_bytes32(amount)),
                    },
                )),
            },
            signature_secret_nonce,
        )?;
        Ok(dotakon::Transaction {
            payload: Some(payload),
            signature: Some(signature),
        })
    }

    pub fn parent_hash(&self) -> Scalar {
        self.parent_hash
    }

    pub fn hash(&self) -> Scalar {
        self.hash
    }

    pub fn diff(&self) -> dotakon::Transaction {
        dotakon::Transaction {
            payload: Some(self.payload.clone()),
            signature: Some(self.signature.clone()),
        }
    }

    pub fn signer(&self) -> Scalar {
        proto::pallas_scalar_from_bytes32(&self.signature.signer.unwrap()).unwrap()
    }

    pub fn payload(&self) -> dotakon::transaction::Payload {
        self.payload
            .to_msg::<dotakon::transaction::Payload>()
            .unwrap()
    }
}

impl mpt::PoseidonHash for Transaction {
    fn poseidon_hash(&self) -> Scalar {
        self.hash
    }
}

fn make_genesis_block(timestamp: SystemTime, network_topology_root_hash: Scalar) -> BlockInfo {
    let block_number = 0;
    let account_balances_root_hash = mpt::AccountBalanceTree::default().root_hash(block_number);
    let program_storage_root_hash = mpt::ProgramStorageTree::default().root_hash(block_number);
    BlockInfo::new(
        block_number,
        Scalar::ZERO,
        timestamp,
        network_topology_root_hash,
        Scalar::ZERO,
        account_balances_root_hash,
        program_storage_root_hash,
    )
}

struct Repr {
    blocks: Vec<BlockInfo>,
    block_numbers_by_hash: BTreeMap<Scalar, usize>,
    network_topologies: BTreeMap<u64, topology::Network>,
    transactions: BTreeMap<Scalar, Transaction>,
    account_balances: mpt::AccountBalanceTree,
    program_storage: mpt::ProgramStorageTree,
}

impl Repr {
    fn new(clock: &Arc<dyn Clock>, identity: dotakon::NodeIdentity) -> Result<Self> {
        let network = topology::Network::new(identity)?;
        let genesis_block = make_genesis_block(clock.now(), network.root_hash());
        Ok(Self {
            blocks: vec![genesis_block],
            block_numbers_by_hash: BTreeMap::from([(genesis_block.hash, 0)]),
            network_topologies: BTreeMap::from([(0, network)]),
            transactions: BTreeMap::new(),
            account_balances: mpt::AccountBalanceTree::default(),
            program_storage: mpt::ProgramStorageTree::default(),
        })
    }

    fn current_version(&self) -> u64 {
        self.blocks.len() as u64
    }

    fn get_block_by_number(&self, block_number: usize) -> Option<BlockInfo> {
        if block_number < self.blocks.len() {
            Some(self.blocks[block_number])
        } else {
            None
        }
    }

    fn get_block_by_hash(&self, block_hash: Scalar) -> Option<BlockInfo> {
        if let Some(block_number) = self.block_numbers_by_hash.get(&block_hash) {
            self.get_block_by_number(*block_number)
        } else {
            None
        }
    }

    fn get_latest_block(&self) -> BlockInfo {
        self.blocks[self.blocks.len() - 1]
    }

    fn get_transaction(&self, hash: Scalar) -> Option<Transaction> {
        self.transactions.get(&hash).cloned()
    }

    fn get_balance(
        &self,
        account_address: Scalar,
        block_hash: Scalar,
    ) -> Result<(BlockInfo, mpt::AccountBalanceProof)> {
        match self.get_block_by_hash(block_hash) {
            Some(block) => Ok((
                block,
                self.account_balances
                    .get_proof(account_address, block.number),
            )),
            None => Err(anyhow!("block not found")),
        }
    }

    fn get_latest_balance(
        &self,
        account_address: Scalar,
    ) -> Result<(BlockInfo, mpt::AccountBalanceProof)> {
        let block = self.get_latest_block();
        Ok((
            block,
            self.account_balances
                .get_proof(account_address, block.number),
        ))
    }
}

pub struct Db {
    clock: Arc<dyn Clock>,
    repr: Mutex<Repr>,
}

impl Db {
    pub fn new(clock: Arc<dyn Clock>, identity: dotakon::NodeIdentity) -> Result<Self> {
        let repr = Repr::new(&clock, identity)?;
        Ok(Self {
            clock,
            repr: Mutex::new(repr),
        })
    }

    pub fn current_version(&self) -> u64 {
        self.repr.lock().unwrap().current_version()
    }

    pub fn get_block_by_number(&self, block_number: usize) -> Option<BlockInfo> {
        self.repr.lock().unwrap().get_block_by_number(block_number)
    }

    pub fn get_block_by_hash(&self, block_hash: Scalar) -> Option<BlockInfo> {
        self.repr.lock().unwrap().get_block_by_hash(block_hash)
    }

    pub fn get_latest_block(&self) -> BlockInfo {
        self.repr.lock().unwrap().get_latest_block()
    }

    pub fn get_transaction(&self, hash: Scalar) -> Option<Transaction> {
        self.repr.lock().unwrap().get_transaction(hash)
    }

    pub fn get_balance(
        &self,
        account_address: Scalar,
        block_hash: Scalar,
    ) -> Result<(BlockInfo, mpt::AccountBalanceProof)> {
        self.repr
            .lock()
            .unwrap()
            .get_balance(account_address, block_hash)
    }

    pub fn get_latest_balance(
        &self,
        account_address: Scalar,
    ) -> Result<(BlockInfo, mpt::AccountBalanceProof)> {
        self.repr
            .lock()
            .unwrap()
            .get_latest_balance(account_address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::test::MockClock;
    use crate::keys;
    use crate::mpt::PoseidonHash;
    use crate::utils;
    use crate::version;
    use ff::PrimeField;
    use pasta_curves::pallas::Point;
    use std::time::Duration;

    fn mock_clock(start_time: SystemTime) -> Arc<dyn Clock> {
        Arc::new(MockClock::new(start_time))
    }

    fn default_mock_clock() -> Arc<dyn Clock> {
        Arc::new(MockClock::default())
    }

    fn testing_identity() -> dotakon::NodeIdentity {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = keys::KeyManager::new(secret_key);
        let identity = dotakon::node_identity::Payload {
            protocol_version: Some(dotakon::ProtocolVersion {
                major: Some(version::PROTOCOL_VERSION_MAJOR),
                minor: Some(version::PROTOCOL_VERSION_MINOR),
                build: Some(version::PROTOCOL_VERSION_BUILD),
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
        dotakon::NodeIdentity {
            payload: Some(payload),
            signature: Some(signature),
        }
    }

    fn genesis_block_hash() -> Scalar {
        utils::u256_to_pallas_scalar(
            "0x0040432efa8475c5694a17712f677108a6fbe623a977f99802ebedc0f17afe91"
                .parse()
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_block_info() {
        let previous_block_hash = Scalar::from_repr_vartime([
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 0,
        ])
        .unwrap();
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(71104);
        let network_topology_root_hash = Scalar::from_repr_vartime([
            8u8, 7, 6, 5, 4, 3, 2, 1, 16, 15, 14, 13, 12, 11, 10, 9, 24, 23, 22, 21, 20, 19, 18,
            17, 32, 31, 30, 29, 28, 27, 26, 0,
        ])
        .unwrap();
        let last_transaction_hash = Scalar::from_repr_vartime([
            31u8, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
            10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        ])
        .unwrap();
        let account_balances_root_hash = Scalar::from_repr_vartime([
            25u8, 26, 27, 28, 29, 30, 31, 32, 17, 18, 19, 20, 21, 22, 23, 24, 9, 10, 11, 12, 13,
            14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 0,
        ])
        .unwrap();
        let program_storage_root_hash = Scalar::from_repr_vartime([
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 15, 14, 13, 12, 11, 10, 9, 8,
            7, 6, 5, 4, 3, 2, 1, 0,
        ])
        .unwrap();
        let block = BlockInfo::new(
            42,
            previous_block_hash,
            timestamp,
            network_topology_root_hash,
            last_transaction_hash,
            account_balances_root_hash,
            program_storage_root_hash,
        );
        assert_ne!(
            block,
            make_genesis_block(timestamp, network_topology_root_hash)
        );
        assert_eq!(
            block.hash(),
            utils::parse_pallas_scalar(
                "0x0958e9d272f41f0431ee81828cd67e51444de1524eed55699196aa6a7e7caffb"
            )
        );
        assert_eq!(block.number(), 42);
        assert_eq!(block.previous_block_hash(), previous_block_hash);
        assert_eq!(block.timestamp(), timestamp);
        assert_eq!(
            block.network_topology_root_hash(),
            network_topology_root_hash
        );
        assert_eq!(block.last_transaction_hash(), last_transaction_hash);
        assert_eq!(
            block.account_balances_root_hash(),
            account_balances_root_hash
        );
        assert_eq!(block.program_storage_root_hash(), program_storage_root_hash);
        assert_eq!(BlockInfo::decode(&block.encode()).unwrap(), block);
    }

    #[test]
    fn test_genesis_block() {
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(71104);
        let network = topology::Network::new(testing_identity()).unwrap();
        let block = make_genesis_block(timestamp, network.root_hash());
        assert_eq!(block.hash(), genesis_block_hash());
        assert_eq!(block.number(), 0);
        assert_eq!(block.previous_block_hash(), Scalar::ZERO);
        assert_eq!(block.timestamp(), timestamp);
        assert_eq!(block.network_topology_root_hash(), network.root_hash());
        assert_eq!(block.last_transaction_hash(), Scalar::ZERO);
        assert_eq!(
            block.account_balances_root_hash(),
            utils::parse_pallas_scalar(
                "0x375830d6862157562431f637dcb4aa91e2bba7220abfa58b7618a713e9bb8803"
            )
        );
        assert_eq!(
            block.program_storage_root_hash(),
            utils::parse_pallas_scalar(
                "0x22eb7ecec06c24f54d23ed5098b765d728698f22a5749a7404ba055475fa296d"
            )
        );
        assert_eq!(BlockInfo::decode(&block.encode()).unwrap(), block);
    }

    #[test]
    fn test_coin_transfer_transaction() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = keys::KeyManager::new(secret_key);
        let parent_hash = Scalar::from_repr_vartime([
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 0,
        ])
        .unwrap();
        let proto = Transaction::make_coin_transfer_proto(
            &key_manager,
            H256::from_slice(&[
                8u8, 7, 6, 5, 4, 3, 2, 1, 16, 15, 14, 13, 12, 11, 10, 9, 24, 23, 22, 21, 20, 19,
                18, 17, 32, 31, 30, 29, 28, 27, 26, 25,
            ]),
            42,
            Scalar::from_repr_vartime([
                31u8, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
            ])
            .unwrap(),
            123.into(),
        )
        .unwrap();
        let tx = Transaction::from_proto(parent_hash, proto.clone()).unwrap();
        assert_eq!(tx.parent_hash(), parent_hash);
        assert_eq!(tx.diff(), proto);
        assert_eq!(tx.signer(), key_manager.wallet_address());
        assert_eq!(
            tx.payload(),
            proto
                .payload
                .unwrap()
                .to_msg::<dotakon::transaction::Payload>()
                .unwrap()
        );
        assert_eq!(
            tx.hash(),
            utils::parse_pallas_scalar(
                "0x3d38b1d2e1223cc513421af87fc664bdac7a903d231be80329cfb309d69ab6f9"
            )
        );
        assert_eq!(tx.poseidon_hash(), tx.hash());
    }

    #[test]
    fn test_coin_transfer_transaction_hash1() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = keys::KeyManager::new(secret_key);
        let tx_proto1 = Transaction::make_coin_transfer_proto(
            &key_manager,
            H256::from_slice(&[
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
            42,
            Scalar::from_repr_vartime([
                31u8, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
            ])
            .unwrap(),
            123.into(),
        )
        .unwrap();
        let tx1 = Transaction::from_proto(Scalar::ZERO, tx_proto1.clone()).unwrap();
        let tx_proto2 = Transaction::make_coin_transfer_proto(
            &key_manager,
            H256::from_slice(&[
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
            42,
            Scalar::from_repr_vartime([
                31u8, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
            ])
            .unwrap(),
            123.into(),
        )
        .unwrap();
        let tx2 = Transaction::from_proto(Scalar::ZERO, tx_proto2.clone()).unwrap();
        assert_eq!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn test_coin_transfer_transaction_hash2() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = keys::KeyManager::new(secret_key);
        let tx_proto1 = Transaction::make_coin_transfer_proto(
            &key_manager,
            H256::from_slice(&[
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
            42,
            Scalar::from_repr_vartime([
                31u8, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
            ])
            .unwrap(),
            123.into(),
        )
        .unwrap();
        let tx1 = Transaction::from_proto(Scalar::ZERO, tx_proto1.clone()).unwrap();
        let tx_proto2 = Transaction::make_coin_transfer_proto(
            &key_manager,
            H256::from_slice(&[
                32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
                12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
            ]),
            42,
            Scalar::from_repr_vartime([
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 0,
            ])
            .unwrap(),
            123.into(),
        )
        .unwrap();
        let tx2 = Transaction::from_proto(Scalar::ZERO, tx_proto2.clone()).unwrap();
        assert_ne!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn test_coin_transfer_transaction_hash3() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = keys::KeyManager::new(secret_key);
        let tx_proto1 = Transaction::make_coin_transfer_proto(
            &key_manager,
            H256::from_slice(&[
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
            42,
            Scalar::from_repr_vartime([
                31u8, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
            ])
            .unwrap(),
            123.into(),
        )
        .unwrap();
        let tx1 = Transaction::from_proto(Scalar::ZERO, tx_proto1.clone()).unwrap();
        let tx_proto2 = Transaction::make_coin_transfer_proto(
            &key_manager,
            H256::from_slice(&[
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
            42,
            Scalar::from_repr_vartime([
                31u8, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
            ])
            .unwrap(),
            123.into(),
        )
        .unwrap();
        let tx2 = Transaction::from_proto(
            Scalar::from_repr_vartime([
                8u8, 7, 6, 5, 4, 3, 2, 1, 16, 15, 14, 13, 12, 11, 10, 9, 24, 23, 22, 21, 20, 19,
                18, 17, 32, 31, 30, 29, 28, 27, 26, 0,
            ])
            .unwrap(),
            tx_proto2.clone(),
        )
        .unwrap();
        assert_ne!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn test_initial_state() {
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let db = Db::new(clock, testing_identity()).unwrap();
        assert_eq!(db.current_version(), 1);
        let genesis_block_hash = genesis_block_hash();
        assert_eq!(
            db.get_block_by_number(0).unwrap().hash(),
            genesis_block_hash
        );
        assert_eq!(
            db.get_block_by_hash(genesis_block_hash).unwrap().hash(),
            genesis_block_hash
        );
        assert_eq!(db.get_latest_block().hash(), genesis_block_hash);
        assert!(
            db.get_transaction(
                Scalar::from_repr_vartime([
                    1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0,
                ])
                .unwrap()
            )
            .is_none()
        );
    }

    fn test_initial_balance(public_key: Point) {
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let db = Db::new(clock, testing_identity()).unwrap();
        let account_address = utils::public_key_to_wallet_address(public_key);
        let (block, proof) = db.get_latest_balance(account_address).unwrap();
        assert_eq!(block.hash(), genesis_block_hash());
        assert_eq!(*proof.key(), account_address);
        assert!(proof.value().is_none());
    }

    #[test]
    fn test_initial_balance1() {
        let (_, public_key, _) = utils::testing_keys1();
        test_initial_balance(public_key);
    }

    #[test]
    fn test_initial_balance2() {
        let (_, public_key, _) = utils::testing_keys2();
        test_initial_balance(public_key);
    }

    fn test_balance_at_first_block(public_key: Point) {
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let db = Db::new(clock, testing_identity()).unwrap();
        let account_address = utils::public_key_to_wallet_address(public_key);
        let (block, proof) = db
            .get_balance(account_address, genesis_block_hash())
            .unwrap();
        assert_eq!(block.hash(), genesis_block_hash());
        assert_eq!(*proof.key(), account_address);
        assert!(proof.value().is_none());
    }

    #[test]
    fn test_balance_at_first_block1() {
        let (_, public_key, _) = utils::testing_keys1();
        test_balance_at_first_block(public_key);
    }

    #[test]
    fn test_balance_at_first_block2() {
        let (_, public_key, _) = utils::testing_keys2();
        test_balance_at_first_block(public_key);
    }

    // TODO
}
