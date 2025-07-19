use crate::clock::Clock;
use crate::dotakon;
use crate::keys;
use crate::mpt;
use crate::proto;
use crate::topology;
use crate::version;
use anyhow::{Context, Result, anyhow};
use base64::{Engine, prelude::BASE64_STANDARD};
use primitive_types::{H256, U256};
use sha3::{self, Digest};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

pub const ACCOUNT_ADDRESS_KEY_LENGTH: usize = 32;
pub const PROGRAM_STORAGE_KEY_LENGTH: usize = 40;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    hash: H256,
    number: u64,
    previous_block_hash: H256,
    timestamp: SystemTime,
    network_topology_root_hash: H256,
    last_transaction_hash: H256,
    account_balances_root_hash: H256,
    program_storage_root_hash: H256,
}

impl BlockInfo {
    fn hash_block(
        block_number: u64,
        previous_block_hash: H256,
        timestamp: SystemTime,
        network_topology_root_hash: H256,
        last_transaction_hash: H256,
        account_balances_root_hash: H256,
        program_storage_root_hash: H256,
    ) -> H256 {
        let message = format!(
            "{{domain=\"{}\",number={},previous={:#x},timestamp={},network={:#x},transactions={:#x},balances={:#x},programs={:#x}}}",
            version::BLOCK_HASH_DOMAIN_SEPARATOR,
            block_number,
            previous_block_hash,
            timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            network_topology_root_hash,
            last_transaction_hash,
            account_balances_root_hash,
            program_storage_root_hash,
        );
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(message.as_bytes());
        H256::from_slice(hasher.finalize().as_slice())
    }

    fn new(
        block_number: u64,
        previous_block_hash: H256,
        timestamp: SystemTime,
        network_topology_root_hash: H256,
        last_transaction_hash: H256,
        account_balances_root_hash: H256,
        program_storage_root_hash: H256,
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

    pub fn hash(&self) -> H256 {
        self.hash
    }

    pub fn number(&self) -> u64 {
        self.number
    }

    pub fn previous_block_hash(&self) -> H256 {
        self.previous_block_hash
    }

    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    pub fn network_topology_root_hash(&self) -> H256 {
        self.network_topology_root_hash
    }

    pub fn last_transaction_hash(&self) -> H256 {
        self.last_transaction_hash
    }

    pub fn account_balances_root_hash(&self) -> H256 {
        self.account_balances_root_hash
    }

    pub fn program_storage_root_hash(&self) -> H256 {
        self.program_storage_root_hash
    }

    pub fn encode(&self) -> dotakon::BlockDescriptor {
        dotakon::BlockDescriptor {
            block_hash: Some(proto::h256_to_bytes32(self.hash)),
            block_number: Some(self.number),
            previous_block_hash: Some(proto::h256_to_bytes32(self.previous_block_hash)),
            timestamp: Some(self.timestamp.into()),
            network_topology_root_hash: Some(proto::h256_to_bytes32(
                self.network_topology_root_hash,
            )),
            last_transaction_hash: Some(proto::h256_to_bytes32(self.last_transaction_hash)),
            account_balances_root_hash: Some(proto::h256_to_bytes32(
                self.account_balances_root_hash,
            )),
            program_storage_root_hash: Some(proto::h256_to_bytes32(self.program_storage_root_hash)),
        }
    }

    pub fn decode(proto: &dotakon::BlockDescriptor) -> Result<BlockInfo> {
        let block_hash =
            proto::h256_from_bytes32(&proto.block_hash.context("block hash field is missing")?);
        let block_number = proto
            .block_number
            .context("block number field is missing")?;
        let previous_block_hash = proto::h256_from_bytes32(
            &proto
                .previous_block_hash
                .context("previous block hash field is missing")?,
        );
        let timestamp: SystemTime = proto
            .timestamp
            .context("timestamp field is missing")?
            .try_into()?;
        let network_topology_root_hash = proto::h256_from_bytes32(
            &proto
                .network_topology_root_hash
                .context("network topology root hash field is missing")?,
        );
        let last_transaction_hash = proto::h256_from_bytes32(
            &proto
                .last_transaction_hash
                .context("last transaction hash field is missing")?,
        );
        let account_balances_root_hash = proto::h256_from_bytes32(
            &proto
                .account_balances_root_hash
                .context("account balance root hash field is missing")?,
        );
        let program_storage_root_hash = proto::h256_from_bytes32(
            &proto
                .program_storage_root_hash
                .context("program storage root hash field is missing")?,
        );
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

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountBalance {
    value: U256,
}

impl AccountBalance {
    pub fn value(&self) -> U256 {
        self.value
    }
}

impl From<U256> for AccountBalance {
    fn from(value: U256) -> Self {
        Self { value }
    }
}

impl From<AccountBalance> for U256 {
    fn from(balance: AccountBalance) -> Self {
        balance.value
    }
}

impl mpt::Sha3Hash for AccountBalance {
    fn sha3_hash(&self) -> primitive_types::H256 {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(self.value.to_little_endian());
        H256::from_slice(hasher.finalize().as_slice())
    }
}

impl mpt::Proto for AccountBalance {
    fn encode(&self) -> Result<prost_types::Any> {
        Ok(prost_types::Any::from_msg(&proto::u256_to_bytes32(
            self.value,
        ))?)
    }

    fn decode(proto: &prost_types::Any) -> Result<Self> {
        Ok(Self {
            value: proto::u256_from_bytes32(&proto.to_msg()?),
        })
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProgramStorageKey {
    pub program_address: H256,
    pub memory_address: u64,
}

impl ProgramStorageKey {
    pub fn encode(&self) -> [u8; PROGRAM_STORAGE_KEY_LENGTH] {
        let mut key = [0u8; PROGRAM_STORAGE_KEY_LENGTH];
        key.copy_from_slice(&self.program_address.to_fixed_bytes());
        key.copy_from_slice(&self.memory_address.to_be_bytes());
        key
    }

    pub fn decode(bytes: &[u8; PROGRAM_STORAGE_KEY_LENGTH]) -> Self {
        let program_address = H256::from_slice(&bytes[0..32]);
        let mut memory_address_bytes = [0u8; 8];
        memory_address_bytes.copy_from_slice(&bytes[32..]);
        let memory_address = u64::from_be_bytes(memory_address_bytes);
        Self {
            program_address,
            memory_address,
        }
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProgramStorageValue {
    value: u64,
}

impl ProgramStorageValue {
    pub fn value(&self) -> u64 {
        self.value
    }
}

impl From<u64> for ProgramStorageValue {
    fn from(value: u64) -> Self {
        Self { value }
    }
}

impl From<ProgramStorageValue> for u64 {
    fn from(value: ProgramStorageValue) -> Self {
        value.value
    }
}

impl mpt::Sha3Hash for ProgramStorageValue {
    fn sha3_hash(&self) -> primitive_types::H256 {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(self.value.to_le_bytes());
        H256::from_slice(hasher.finalize().as_slice())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Transaction {
    parent_hash: H256,
    payload: prost_types::Any,
    signature: dotakon::Signature,
    hash: H256,
}

impl Transaction {
    fn hash_transfer_coins_transaction(
        parent_hash: H256,
        nonce: u64,
        sender_address: H256,
        transaction: &dotakon::transaction::TransferCoins,
    ) -> Result<H256> {
        let message = format!(
            "{{domain=\"{}\",parent_hash={:#x},sender={:#x},nonce={},type=\"transfer-coins\",recipient={:#x},amount={}}}",
            version::TRANSACTION_HASH_DOMAIN_SEPARATOR,
            parent_hash,
            sender_address,
            nonce,
            proto::h256_from_bytes32(
                &transaction
                    .recipient
                    .context("invalid coin transfer transaction: recipient field is missing")?
            ),
            proto::u256_from_bytes32(
                &transaction
                    .amount
                    .context("invalid coin transfer transaction: amount field is missing")?
            ),
        );
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(message.as_bytes());
        Ok(H256::from_slice(hasher.finalize().as_slice()))
    }

    fn hash_create_program_transaction(
        parent_hash: H256,
        nonce: u64,
        sender_address: H256,
        transaction: &dotakon::transaction::CreateProgram,
    ) -> Result<H256> {
        let message = format!(
            "{{domain=\"{}\",parent_hash={:#x},nonce={},sender={:#x},type=\"create-program\",bytecode=\"{}\"}}",
            version::TRANSACTION_HASH_DOMAIN_SEPARATOR,
            parent_hash,
            nonce,
            sender_address,
            BASE64_STANDARD.encode(
                transaction
                    .bytecode
                    .as_ref()
                    .context("invalid smartcontract deployment transaction: bytecode is missing")?
                    .as_slice()
            ),
        );
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(message.as_bytes());
        Ok(H256::from_slice(hasher.finalize().as_slice()))
    }

    fn from_proto_impl(
        parent_hash: H256,
        payload: prost_types::Any,
        signature: dotakon::Signature,
    ) -> Result<Self> {
        let decoded = payload.to_msg::<dotakon::transaction::Payload>()?;
        let nonce = decoded
            .nonce
            .context("invalid transaction: nonce field is missing")?;
        let signer =
            proto::h256_from_bytes32(&signature.signer.context("invalid transaction signature")?);
        let hash = match &decoded.transaction.context("invalid transaction")? {
            dotakon::transaction::payload::Transaction::TransferCoins(transaction) => {
                Self::hash_transfer_coins_transaction(parent_hash, nonce, signer, transaction)
            }
            dotakon::transaction::payload::Transaction::CreateProgram(transaction) => {
                Self::hash_create_program_transaction(parent_hash, nonce, signer, transaction)
            }
        }?;
        Ok(Self {
            parent_hash,
            payload,
            signature,
            hash,
        })
    }

    pub fn from_proto(parent_hash: H256, proto: dotakon::Transaction) -> Result<Self> {
        let payload = proto.payload.context("invalid transaction")?;
        let signature = proto.signature.context("the transaction is not signed")?;
        Self::from_proto_impl(parent_hash, payload, signature)
    }

    pub fn from_proto_verify(parent_hash: H256, proto: dotakon::Transaction) -> Result<Self> {
        let payload = proto.payload.context("invalid transaction")?;
        let signature = proto.signature.context("the transaction is not signed")?;
        keys::KeyManager::verify_signed_message(&payload, &signature)?;
        Self::from_proto_impl(parent_hash, payload, signature)
    }

    pub fn make_coin_transfer_proto(
        key_manager: &keys::KeyManager,
        signature_secret_nonce: H256,
        transaction_nonce: u64,
        recipient_address: H256,
        amount: U256,
    ) -> Result<dotakon::Transaction> {
        let (payload, signature) = key_manager.sign_message(
            &dotakon::transaction::Payload {
                nonce: Some(transaction_nonce),
                transaction: Some(dotakon::transaction::payload::Transaction::TransferCoins(
                    dotakon::transaction::TransferCoins {
                        recipient: Some(proto::h256_to_bytes32(recipient_address)),
                        amount: Some(proto::u256_to_bytes32(amount)),
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

    pub fn parent_hash(&self) -> H256 {
        self.parent_hash
    }

    pub fn hash(&self) -> H256 {
        self.hash
    }

    pub fn diff(&self) -> dotakon::Transaction {
        dotakon::Transaction {
            payload: Some(self.payload.clone()),
            signature: Some(self.signature.clone()),
        }
    }

    pub fn signer(&self) -> H256 {
        proto::h256_from_bytes32(&self.signature.signer.unwrap())
    }

    pub fn payload(&self) -> dotakon::transaction::Payload {
        self.payload
            .to_msg::<dotakon::transaction::Payload>()
            .unwrap()
    }
}

impl mpt::Sha3Hash for Transaction {
    fn sha3_hash(&self) -> H256 {
        self.hash
    }
}

type AccountBalances = mpt::MPT<AccountBalance, ACCOUNT_ADDRESS_KEY_LENGTH>;
pub type AccountBalanceProof = mpt::Proof<AccountBalance, ACCOUNT_ADDRESS_KEY_LENGTH>;

type ProgramStorage = mpt::MPT<ProgramStorageValue, PROGRAM_STORAGE_KEY_LENGTH>;
pub type ProgramStorageProof = mpt::Proof<ProgramStorageValue, PROGRAM_STORAGE_KEY_LENGTH>;

fn make_genesis_block(timestamp: SystemTime, network_topology_root_hash: H256) -> BlockInfo {
    let block_number = 0;
    let previous_block_hash = H256::zero();
    let account_balances_root_hash = AccountBalances::new().root_hash(block_number);
    let program_storage_root_hash = ProgramStorage::new().root_hash(block_number);
    BlockInfo::new(
        block_number,
        previous_block_hash,
        timestamp,
        network_topology_root_hash,
        H256::zero(),
        account_balances_root_hash,
        program_storage_root_hash,
    )
}

pub struct Db {
    clock: Arc<dyn Clock>,
    blocks: Vec<BlockInfo>,
    block_numbers_by_hash: BTreeMap<H256, usize>,
    network_topologies: BTreeMap<u64, topology::Network>,
    transactions: BTreeMap<H256, Transaction>,
    account_balances: AccountBalances,
    program_storage: ProgramStorage,
}

impl Db {
    pub fn new(clock: Arc<dyn Clock>, identity: dotakon::NodeIdentity) -> Result<Self> {
        let network = topology::Network::new(identity)?;
        let genesis_block = make_genesis_block(clock.now(), network.root_hash());
        Ok(Self {
            clock,
            blocks: vec![genesis_block],
            block_numbers_by_hash: BTreeMap::from([(genesis_block.hash, 0)]),
            network_topologies: BTreeMap::from([(0, network)]),
            transactions: BTreeMap::from([]),
            account_balances: AccountBalances::new(),
            program_storage: ProgramStorage::new(),
        })
    }

    pub fn current_version(&self) -> u64 {
        self.blocks.len() as u64
    }

    pub fn get_block_by_number(&self, block_number: usize) -> Option<&BlockInfo> {
        if block_number < self.blocks.len() {
            Some(&self.blocks[block_number])
        } else {
            None
        }
    }

    pub fn get_block_by_hash(&self, block_hash: H256) -> Option<&BlockInfo> {
        if let Some(block_number) = self.block_numbers_by_hash.get(&block_hash) {
            self.get_block_by_number(*block_number)
        } else {
            None
        }
    }

    pub fn get_latest_block(&self) -> &BlockInfo {
        &self.blocks[self.blocks.len() - 1]
    }

    pub fn get_transaction(&self, hash: H256) -> Option<&Transaction> {
        self.transactions.get(&hash)
    }

    pub fn get_balance(
        &self,
        account_address: H256,
        block_hash: H256,
    ) -> Result<(BlockInfo, AccountBalanceProof)> {
        if let Some(block) = self.get_block_by_hash(block_hash) {
            Ok((
                *block,
                self.account_balances
                    .get_proof(&account_address.to_fixed_bytes(), block.number)?,
            ))
        } else {
            Err(anyhow!("block not found"))
        }
    }

    pub fn get_latest_balance(
        &self,
        account_address: H256,
    ) -> Result<(BlockInfo, AccountBalanceProof)> {
        let block = self.get_latest_block();
        Ok((
            *block,
            self.account_balances
                .get_proof(&account_address.to_fixed_bytes(), block.number)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::test::MockClock;
    use crate::keys;
    use crate::mpt::{Proto, Sha3Hash};
    use crate::utils;
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
        dotakon::NodeIdentity {
            payload: Some(payload),
            signature: Some(signature),
        }
    }

    fn genesis_block_hash() -> H256 {
        "0x06cd735786d99bb1263b40ef8a7409a9631e403de0032aa90a85f8c319ca8530"
            .parse()
            .unwrap()
    }

    #[test]
    fn test_block_info() {
        let previous_block_hash = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(71104);
        let network_topology_root_hash = H256::from_slice(&[
            8u8, 7, 6, 5, 4, 3, 2, 1, 16, 15, 14, 13, 12, 11, 10, 9, 24, 23, 22, 21, 20, 19, 18,
            17, 32, 31, 30, 29, 28, 27, 26, 25,
        ]);
        let last_transaction_hash = H256::from_slice(&[
            32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
            11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
        ]);
        let account_balances_root_hash = H256::from_slice(&[
            25u8, 26, 27, 28, 29, 30, 31, 32, 17, 18, 19, 20, 21, 22, 23, 24, 9, 10, 11, 12, 13,
            14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8,
        ]);
        let program_storage_root_hash = H256::from_slice(&[
            2u8, 1, 4, 3, 6, 5, 8, 7, 10, 9, 12, 11, 14, 13, 16, 15, 18, 17, 20, 19, 22, 21, 24,
            23, 26, 25, 28, 27, 30, 29, 32, 31,
        ]);
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
            "0xb5664994b0be201b2400bc7f5c604be85b06859dabe71313eda2f79b10e1b88d"
                .parse()
                .unwrap()
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
        assert_eq!(block.previous_block_hash(), H256::zero());
        assert_eq!(block.timestamp(), timestamp);
        assert_eq!(block.network_topology_root_hash(), network.root_hash());
        assert_eq!(block.last_transaction_hash(), H256::zero());
        assert_eq!(
            block.account_balances_root_hash(),
            "0xb4a3716bd9261f312ea71656dda4caa0d694f0f6816712036ee8fce833e4b46f"
                .parse()
                .unwrap()
        );
        assert_eq!(
            block.program_storage_root_hash(),
            "0xb4a3716bd9261f312ea71656dda4caa0d694f0f6816712036ee8fce833e4b46f"
                .parse()
                .unwrap()
        );
        assert_eq!(BlockInfo::decode(&block.encode()).unwrap(), block);
    }

    #[test]
    fn test_coin_transfer_transaction() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = keys::KeyManager::new(secret_key);
        let parent_hash = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        let proto = Transaction::make_coin_transfer_proto(
            &key_manager,
            H256::from_slice(&[
                8u8, 7, 6, 5, 4, 3, 2, 1, 16, 15, 14, 13, 12, 11, 10, 9, 24, 23, 22, 21, 20, 19,
                18, 17, 32, 31, 30, 29, 28, 27, 26, 25,
            ]),
            42,
            H256::from_slice(&[
                32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
                12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
            ]),
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
            "0x6b13bb5d838bf226cce0e7cca39eded2f688e53b31d7bde3b7edb86430ef60d0"
                .parse()
                .unwrap()
        );
        assert_eq!(tx.sha3_hash(), tx.hash());
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
            H256::from_slice(&[
                32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
                12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
            ]),
            123.into(),
        )
        .unwrap();
        let tx1 = Transaction::from_proto(H256::zero(), tx_proto1.clone()).unwrap();
        let tx_proto2 = Transaction::make_coin_transfer_proto(
            &key_manager,
            H256::from_slice(&[
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
            42,
            H256::from_slice(&[
                32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
                12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
            ]),
            123.into(),
        )
        .unwrap();
        let tx2 = Transaction::from_proto(H256::zero(), tx_proto2.clone()).unwrap();
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
            H256::from_slice(&[
                32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
                12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
            ]),
            123.into(),
        )
        .unwrap();
        let tx1 = Transaction::from_proto(H256::zero(), tx_proto1.clone()).unwrap();
        let tx_proto2 = Transaction::make_coin_transfer_proto(
            &key_manager,
            H256::from_slice(&[
                32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
                12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
            ]),
            42,
            H256::from_slice(&[
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
            123.into(),
        )
        .unwrap();
        let tx2 = Transaction::from_proto(H256::zero(), tx_proto2.clone()).unwrap();
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
            H256::from_slice(&[
                32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
                12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
            ]),
            123.into(),
        )
        .unwrap();
        let tx1 = Transaction::from_proto(H256::zero(), tx_proto1.clone()).unwrap();
        let tx_proto2 = Transaction::make_coin_transfer_proto(
            &key_manager,
            H256::from_slice(&[
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
            42,
            H256::from_slice(&[
                32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
                12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
            ]),
            123.into(),
        )
        .unwrap();
        let tx2 = Transaction::from_proto(
            H256::from_slice(&[
                8u8, 7, 6, 5, 4, 3, 2, 1, 16, 15, 14, 13, 12, 11, 10, 9, 24, 23, 22, 21, 20, 19,
                18, 17, 32, 31, 30, 29, 28, 27, 26, 25,
            ]),
            tx_proto2.clone(),
        )
        .unwrap();
        assert_ne!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn test_account_balance() {
        let value = U256::from_little_endian(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        assert_eq!(AccountBalance::from(value), value.into());
        assert_eq!(AccountBalance::from(value).value(), value);
        assert_eq!(value, AccountBalance::from(value).into());
        assert_eq!(
            AccountBalance::from(value).sha3_hash(),
            "0x08d76bb3d477d6f3a5f26cb66c691486547acf9bbac6cfabfba30784c815ae45"
                .parse()
                .unwrap()
        );
        let balance = AccountBalance::from(value);
        assert_eq!(
            AccountBalance::decode(&balance.encode().unwrap()).unwrap(),
            balance
        );
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
            db.get_transaction(H256::from_slice(&[
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]))
            .is_none()
        );
    }

    fn test_initial_balance(public_key: H256) {
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let db = Db::new(clock, testing_identity()).unwrap();
        let account_address = utils::public_key_to_wallet_address(public_key);
        let (block, proof) = db.get_latest_balance(account_address).unwrap();
        assert_eq!(block.hash(), genesis_block_hash());
        assert_eq!(H256::from_slice(proof.key()), account_address);
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

    fn test_balance_at_first_block(public_key: H256) {
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let db = Db::new(clock, testing_identity()).unwrap();
        let account_address = utils::public_key_to_wallet_address(public_key);
        let (block, proof) = db
            .get_balance(account_address, genesis_block_hash())
            .unwrap();
        assert_eq!(block.hash(), genesis_block_hash());
        assert_eq!(H256::from_slice(proof.key()), account_address);
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
