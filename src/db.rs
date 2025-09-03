use crate::clock::Clock;
use crate::dotakon;
use crate::keys;
use crate::proto;
use crate::topology;
use crate::tree::{self, AccountInfo};
use crate::utils;
use crate::utils::PoseidonHash;
use anyhow::{Context, Result, anyhow};
use ff::Field;
use pasta_curves::pallas::Scalar;
use primitive_types::H256;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::Mutex;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    hash: Scalar,
    chain_id: u64,
    number: u64,
    previous_block_hash: Scalar,
    timestamp: SystemTime,
    network_topology_root_hash: Scalar,
    last_transaction_hash: Scalar,
    accounts_root_hash: Scalar,
    program_storage_root_hash: Scalar,
}

impl BlockInfo {
    fn hash_block(
        chain_id: u64,
        block_number: u64,
        previous_block_hash: Scalar,
        timestamp: SystemTime,
        network_topology_root_hash: Scalar,
        last_transaction_hash: Scalar,
        accounts_root_hash: Scalar,
        program_storage_root_hash: Scalar,
    ) -> Scalar {
        utils::poseidon_hash([
            Scalar::from(chain_id),
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
            accounts_root_hash,
            program_storage_root_hash,
        ])
    }

    fn new(
        chain_id: u64,
        block_number: u64,
        previous_block_hash: Scalar,
        timestamp: SystemTime,
        network_topology_root_hash: Scalar,
        last_transaction_hash: Scalar,
        accounts_root_hash: Scalar,
        program_storage_root_hash: Scalar,
    ) -> Self {
        Self {
            hash: Self::hash_block(
                chain_id,
                block_number,
                previous_block_hash,
                timestamp,
                network_topology_root_hash,
                last_transaction_hash,
                accounts_root_hash,
                program_storage_root_hash,
            ),
            chain_id,
            number: block_number,
            previous_block_hash,
            timestamp,
            network_topology_root_hash,
            last_transaction_hash,
            accounts_root_hash,
            program_storage_root_hash,
        }
    }

    pub fn hash(&self) -> Scalar {
        self.hash
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
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

    pub fn accounts_root_hash(&self) -> Scalar {
        self.accounts_root_hash
    }

    pub fn program_storage_root_hash(&self) -> Scalar {
        self.program_storage_root_hash
    }

    pub fn encode(&self) -> dotakon::BlockDescriptor {
        dotakon::BlockDescriptor {
            block_hash: Some(proto::pallas_scalar_to_bytes32(self.hash)),
            chain_id: Some(self.chain_id),
            block_number: Some(self.number),
            previous_block_hash: Some(proto::pallas_scalar_to_bytes32(self.previous_block_hash)),
            timestamp: Some(self.timestamp.into()),
            network_topology_root_hash: Some(proto::pallas_scalar_to_bytes32(
                self.network_topology_root_hash,
            )),
            last_transaction_hash: Some(proto::pallas_scalar_to_bytes32(
                self.last_transaction_hash,
            )),
            accounts_root_hash: Some(proto::pallas_scalar_to_bytes32(self.accounts_root_hash)),
            program_storage_root_hash: Some(proto::pallas_scalar_to_bytes32(
                self.program_storage_root_hash,
            )),
        }
    }

    pub fn decode(proto: &dotakon::BlockDescriptor) -> Result<BlockInfo> {
        let block_hash = proto::pallas_scalar_from_bytes32(
            &proto.block_hash.context("block hash field is missing")?,
        )?;
        let chain_id = proto.chain_id.context("chain ID field is missing")?;
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
        let accounts_root_hash = proto::pallas_scalar_from_bytes32(
            &proto
                .accounts_root_hash
                .context("account balance root hash field is missing")?,
        )?;
        let program_storage_root_hash = proto::pallas_scalar_from_bytes32(
            &proto
                .program_storage_root_hash
                .context("program storage root hash field is missing")?,
        )?;
        let block_info = Self::new(
            chain_id,
            block_number,
            previous_block_hash,
            timestamp,
            network_topology_root_hash,
            last_transaction_hash,
            accounts_root_hash,
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
    fn hash_send_coins_transaction(
        parent_hash: Scalar,
        chain_id: u64,
        nonce: u64,
        sender_address: Scalar,
        transaction: &dotakon::transaction::SendCoins,
    ) -> Result<Scalar> {
        Ok(utils::poseidon_hash([
            parent_hash,
            sender_address,
            chain_id.into(),
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
        let chain_id = decoded
            .chain_id
            .context("invalid transaction: network ID field is missing")?;
        let nonce = decoded
            .nonce
            .context("invalid transaction: nonce field is missing")?;
        let signer = proto::pallas_scalar_from_bytes32(
            &signature.signer.context("invalid transaction signature")?,
        )?;
        let hash = match &decoded.transaction.context("invalid transaction")? {
            dotakon::transaction::payload::Transaction::SendCoins(transaction) => {
                Self::hash_send_coins_transaction(parent_hash, chain_id, nonce, signer, transaction)
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
        secret_signature_nonce: H256,
        chain_id: u64,
        transaction_nonce: u64,
        recipient_address: Scalar,
        amount: Scalar,
    ) -> Result<dotakon::Transaction> {
        let (payload, signature) = key_manager.sign_message(
            &dotakon::transaction::Payload {
                chain_id: Some(chain_id),
                nonce: Some(transaction_nonce),
                transaction: Some(dotakon::transaction::payload::Transaction::SendCoins(
                    dotakon::transaction::SendCoins {
                        recipient: Some(proto::pallas_scalar_to_bytes32(recipient_address)),
                        amount: Some(proto::pallas_scalar_to_bytes32(amount)),
                    },
                )),
            },
            secret_signature_nonce,
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

impl PoseidonHash for Transaction {
    fn poseidon_hash(&self) -> Scalar {
        self.hash
    }
}

fn make_genesis_block(
    chain_id: u64,
    timestamp: SystemTime,
    network_topology_root_hash: Scalar,
    accounts_root_hash: Scalar,
) -> BlockInfo {
    let block_number = 0;
    let program_storage_root_hash = tree::ProgramStorageTree::default().root_hash(block_number);
    BlockInfo::new(
        chain_id,
        block_number,
        Scalar::ZERO,
        timestamp,
        network_topology_root_hash,
        Scalar::ZERO,
        accounts_root_hash,
        program_storage_root_hash,
    )
}

struct Repr {
    chain_id: u64,
    blocks: Vec<BlockInfo>,
    block_numbers_by_hash: BTreeMap<Scalar, usize>,
    network_topologies: BTreeMap<u64, topology::Network>,
    transactions: Vec<Transaction>,
    transactions_by_hash: BTreeMap<Scalar, usize>,
    accounts: tree::AccountTree,
    program_storage: tree::ProgramStorageTree,
}

impl Repr {
    fn new<const N: usize>(
        clock: &Arc<dyn Clock>,
        chain_id: u64,
        identity: dotakon::NodeIdentity,
        initial_accounts: [(Scalar, AccountInfo); N],
    ) -> Result<Self> {
        let network = topology::Network::new(identity)?;
        let accounts = tree::AccountTree::from(initial_accounts);
        let genesis_block = make_genesis_block(
            chain_id,
            clock.now(),
            network.root_hash(),
            accounts.root_hash(0),
        );
        Ok(Self {
            chain_id,
            blocks: vec![genesis_block],
            block_numbers_by_hash: BTreeMap::from([(genesis_block.hash, 0)]),
            network_topologies: BTreeMap::from([(0, network)]),
            transactions: vec![],
            transactions_by_hash: BTreeMap::new(),
            accounts,
            program_storage: tree::ProgramStorageTree::default(),
        })
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
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
        let index = *(self.transactions_by_hash.get(&hash)?);
        Some(self.transactions[index].clone())
    }

    fn get_account_info(
        &self,
        account_address: Scalar,
        block_hash: Scalar,
    ) -> Result<(BlockInfo, tree::AccountProof)> {
        match self.get_block_by_hash(block_hash) {
            Some(block) => Ok((
                block,
                self.accounts.get_proof(account_address, block.number),
            )),
            None => Err(anyhow!("block not found")),
        }
    }

    fn get_latest_account_info(
        &self,
        account_address: Scalar,
    ) -> Result<(BlockInfo, tree::AccountProof)> {
        let block = self.get_latest_block();
        Ok((
            block,
            self.accounts.get_proof(account_address, block.number),
        ))
    }

    fn apply_send_coins_transaction(
        &mut self,
        signer: Scalar,
        payload: &dotakon::transaction::SendCoins,
    ) -> Result<()> {
        let version = self.current_version();
        let recipient = proto::pallas_scalar_from_bytes32(
            &payload
                .recipient
                .context("invalid coin transfer transaction payload: missing recipient")?,
        )?;
        let amount = proto::pallas_scalar_from_bytes32(
            &payload
                .amount
                .context("invalid coin transfer transaction payload: missing amount")?,
        )?;
        let mut signer_account = *self.accounts.get(signer, version);
        let sender_balance = signer_account.balance;
        if sender_balance < amount {
            return Err(anyhow!(
                "insufficient balance for {:#x}: {} available, cannot transfer {}",
                utils::pallas_scalar_to_u256(signer),
                utils::pallas_scalar_to_u256(sender_balance),
                utils::pallas_scalar_to_u256(amount),
            ));
        }
        signer_account.balance -= amount;
        self.accounts.put(signer, signer_account, version);
        let mut recipient_account = *self.accounts.get(recipient, version);
        recipient_account.balance += amount;
        self.accounts.put(recipient, recipient_account, version);
        Ok(())
    }

    fn apply_transaction(&mut self, transaction: &Transaction) -> Result<()> {
        let signer = transaction.signer();
        let payload = &transaction.payload();
        if payload.chain_id() != self.chain_id {
            return Err(anyhow!(
                "invalid chain ID {} (this is network {})",
                payload.chain_id(),
                self.chain_id
            ));
        }
        let block_number = self.current_version();
        let nonce = payload.nonce();
        let signer_account = *self.accounts.get(signer, block_number);
        if nonce <= signer_account.last_nonce {
            return Err(anyhow!(
                "invalid nonce {} (latest for {:#x} is {})",
                nonce,
                utils::pallas_scalar_to_u256(signer),
                signer_account.last_nonce,
            ));
        }
        match &payload.transaction {
            Some(dotakon::transaction::payload::Transaction::SendCoins(payload)) => {
                self.apply_send_coins_transaction(signer, payload)
            }
            Some(dotakon::transaction::payload::Transaction::CreateProgram(_)) => {
                todo!()
            }
            None => Err(anyhow!("invalid transaction payload")),
        }?;
        let mut signer_account = *self.accounts.get(signer, block_number);
        signer_account.last_nonce = nonce;
        self.accounts.put(signer, signer_account, block_number);
        Ok(())
    }

    fn add_transaction(&mut self, transaction: &dotakon::Transaction) -> Result<Scalar> {
        let parent_hash = match self.transactions.last() {
            Some(last_transaction) => last_transaction.hash(),
            None => Scalar::ZERO,
        };
        let transaction = Transaction::from_proto(parent_hash, transaction.clone())?;
        let hash = transaction.hash();
        self.apply_transaction(&transaction)?;
        let index = self.transactions.len();
        self.transactions.push(transaction);
        self.transactions_by_hash.insert(hash, index);
        Ok(hash)
    }

    fn close_block(&mut self, timestamp: SystemTime) -> BlockInfo {
        let block_number = self.current_version();
        let previous_block_hash = self.blocks.last().unwrap().hash();
        let (_, network_topology) = self
            .network_topologies
            .range(0..=block_number)
            .next_back()
            .unwrap();
        let last_transaction_hash = match self.transactions.last() {
            Some(transaction) => transaction.hash(),
            None => Scalar::ZERO,
        };
        let accounts_root_hash = self.accounts.root_hash(block_number);
        let program_storage_root_hash = self.program_storage.root_hash(block_number);
        let block = BlockInfo::new(
            self.chain_id,
            block_number,
            previous_block_hash,
            timestamp,
            network_topology.root_hash(),
            last_transaction_hash,
            accounts_root_hash,
            program_storage_root_hash,
        );
        let block_hash = block.hash();
        self.blocks.push(block);
        self.block_numbers_by_hash
            .insert(block_hash, block_number as usize);
        block
    }
}

pub struct Db {
    clock: Arc<dyn Clock>,
    repr: Mutex<Repr>,
}

impl Db {
    pub fn new<const N: usize>(
        clock: Arc<dyn Clock>,
        chain_id: u64,
        identity: dotakon::NodeIdentity,
        initial_accounts: [(Scalar, AccountInfo); N],
    ) -> Result<Self> {
        let repr = Repr::new(&clock, chain_id, identity, initial_accounts)?;
        Ok(Self {
            clock,
            repr: Mutex::new(repr),
        })
    }

    pub async fn chain_id(&self) -> u64 {
        self.repr.lock().await.chain_id()
    }

    pub async fn current_version(&self) -> u64 {
        self.repr.lock().await.current_version()
    }

    pub async fn get_block_by_number(&self, block_number: usize) -> Option<BlockInfo> {
        self.repr.lock().await.get_block_by_number(block_number)
    }

    pub async fn get_block_by_hash(&self, block_hash: Scalar) -> Option<BlockInfo> {
        self.repr.lock().await.get_block_by_hash(block_hash)
    }

    pub async fn get_latest_block(&self) -> BlockInfo {
        self.repr.lock().await.get_latest_block()
    }

    pub async fn get_account_info(
        &self,
        account_address: Scalar,
        block_hash: Scalar,
    ) -> Result<(BlockInfo, tree::AccountProof)> {
        self.repr
            .lock()
            .await
            .get_account_info(account_address, block_hash)
    }

    pub async fn get_latest_account_info(
        &self,
        account_address: Scalar,
    ) -> Result<(BlockInfo, tree::AccountProof)> {
        self.repr
            .lock()
            .await
            .get_latest_account_info(account_address)
    }

    pub async fn get_transaction(&self, hash: Scalar) -> Option<Transaction> {
        self.repr.lock().await.get_transaction(hash)
    }

    pub async fn add_transaction(&self, transaction: &dotakon::Transaction) -> Result<Scalar> {
        self.repr.lock().await.add_transaction(transaction)
    }

    pub async fn close_block(&self) -> BlockInfo {
        let mut repr = self.repr.lock().await;
        repr.close_block(self.clock.now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::test::MockClock;
    use crate::keys;
    use crate::tree::AccountTree;
    use crate::utils;
    use crate::version;
    use ff::PrimeField;
    use pasta_curves::pallas::Point;
    use tokio::time::Duration;

    const TEST_CHAIN_ID: u64 = 42;

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
            chain_id: Some(TEST_CHAIN_ID),
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

    fn default_genesis_block_hash() -> Scalar {
        utils::u256_to_pallas_scalar(
            "0x279760377f1ebc7931e1804663b301f687630a6144947353b710ed811bfcb2c5"
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
        let accounts_root_hash = Scalar::from_repr_vartime([
            25u8, 26, 27, 28, 29, 30, 31, 32, 17, 18, 19, 20, 21, 22, 23, 24, 9, 10, 11, 12, 13,
            14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 0,
        ])
        .unwrap();
        let program_storage_root_hash = Scalar::from_repr_vartime([
            8u8, 7, 6, 5, 4, 3, 2, 1, 16, 15, 14, 13, 12, 11, 10, 9, 8, 9, 10, 11, 12, 13, 14, 15,
            1, 2, 3, 4, 5, 6, 7, 0,
        ])
        .unwrap();
        let block = BlockInfo::new(
            TEST_CHAIN_ID,
            123,
            previous_block_hash,
            timestamp,
            network_topology_root_hash,
            last_transaction_hash,
            accounts_root_hash,
            program_storage_root_hash,
        );
        assert_ne!(
            block,
            make_genesis_block(
                TEST_CHAIN_ID,
                timestamp,
                network_topology_root_hash,
                accounts_root_hash,
            )
        );
        assert_eq!(
            block.hash(),
            utils::parse_pallas_scalar(
                "0x19f4ce9db0c9abead289f959cbec514cc04b71d867870dc87157c21b4fe66e80"
            )
        );
        assert_eq!(block.chain_id(), TEST_CHAIN_ID);
        assert_eq!(block.number(), 123);
        assert_eq!(block.previous_block_hash(), previous_block_hash);
        assert_eq!(block.timestamp(), timestamp);
        assert_eq!(
            block.network_topology_root_hash(),
            network_topology_root_hash
        );
        assert_eq!(block.last_transaction_hash(), last_transaction_hash);
        assert_eq!(block.accounts_root_hash(), accounts_root_hash);
        assert_eq!(block.program_storage_root_hash(), program_storage_root_hash);
        assert_eq!(BlockInfo::decode(&block.encode()).unwrap(), block);
    }

    #[test]
    fn test_genesis_block() {
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(71104);
        let network = topology::Network::new(testing_identity()).unwrap();
        let accounts = AccountTree::from([]);
        let block = make_genesis_block(
            TEST_CHAIN_ID,
            timestamp,
            network.root_hash(),
            accounts.root_hash(0),
        );
        assert_eq!(block.hash(), default_genesis_block_hash());
        assert_eq!(block.chain_id(), TEST_CHAIN_ID);
        assert_eq!(block.number(), 0);
        assert_eq!(block.previous_block_hash(), Scalar::ZERO);
        assert_eq!(block.timestamp(), timestamp);
        assert_eq!(block.network_topology_root_hash(), network.root_hash());
        assert_eq!(block.last_transaction_hash(), Scalar::ZERO);
        assert_eq!(
            block.accounts_root_hash(),
            utils::parse_pallas_scalar(
                "0x2d79ad7ee66416fc6ddaabd61a1a2d597852c655652ded77128a651f1f0966b4"
            )
        );
        assert_eq!(
            block.program_storage_root_hash(),
            utils::parse_pallas_scalar(
                "0x297401934d5cc4d84e639092ccb6f336faae9fc1c54cd4e23ef2561f8c63f683"
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
            TEST_CHAIN_ID,
            24,
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
                "0x06912fb7025c47d287bca02851286fae708fb79f0c5a7e6c11bf792a50201909"
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
            TEST_CHAIN_ID,
            24,
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
            TEST_CHAIN_ID,
            24,
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
            TEST_CHAIN_ID,
            24,
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
            TEST_CHAIN_ID,
            24,
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
            TEST_CHAIN_ID,
            24,
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
            TEST_CHAIN_ID,
            24,
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
    fn test_coin_transfer_transaction_hash4() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = keys::KeyManager::new(secret_key);
        let tx_proto1 = Transaction::make_coin_transfer_proto(
            &key_manager,
            H256::from_slice(&[
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
            TEST_CHAIN_ID,
            24,
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
            TEST_CHAIN_ID + 1,
            24,
            Scalar::from_repr_vartime([
                31u8, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
            ])
            .unwrap(),
            123.into(),
        )
        .unwrap();
        let tx2 = Transaction::from_proto(Scalar::ZERO, tx_proto2.clone()).unwrap();
        assert_ne!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn test_coin_transfer_transaction_hash5() {
        let (secret_key, _, _) = utils::testing_keys1();
        let key_manager = keys::KeyManager::new(secret_key);
        let tx_proto1 = Transaction::make_coin_transfer_proto(
            &key_manager,
            H256::from_slice(&[
                1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
            TEST_CHAIN_ID,
            24,
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
            TEST_CHAIN_ID,
            25,
            Scalar::from_repr_vartime([
                31u8, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
            ])
            .unwrap(),
            123.into(),
        )
        .unwrap();
        let tx2 = Transaction::from_proto(Scalar::ZERO, tx_proto2.clone()).unwrap();
        assert_ne!(tx1.hash(), tx2.hash());
    }

    #[tokio::test]
    async fn test_initial_state() {
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let db = Db::new(clock, TEST_CHAIN_ID, testing_identity(), []).unwrap();
        assert_eq!(db.chain_id().await, TEST_CHAIN_ID);
        assert_eq!(db.current_version().await, 1);
        let block_hash = default_genesis_block_hash();
        assert_eq!(db.get_block_by_number(0).await.unwrap().hash(), block_hash);
        assert_eq!(
            db.get_block_by_hash(block_hash).await.unwrap().hash(),
            block_hash
        );
        assert_eq!(db.get_latest_block().await.hash(), block_hash);
        assert!(
            db.get_transaction(
                Scalar::from_repr_vartime([
                    1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0,
                ])
                .unwrap()
            )
            .await
            .is_none()
        );
    }

    async fn test_initial_account_state(public_key: Point) {
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let db = Db::new(clock, TEST_CHAIN_ID, testing_identity(), []).unwrap();
        let account_address = utils::public_key_to_wallet_address(public_key);
        let (block, proof) = db.get_latest_account_info(account_address).await.unwrap();
        assert_eq!(block.hash(), default_genesis_block_hash());
        assert_eq!(proof.key(), account_address);
        assert_eq!(*proof.value(), AccountInfo::default());
    }

    #[tokio::test]
    async fn test_initial_account_state1() {
        let (_, public_key, _) = utils::testing_keys1();
        test_initial_account_state(public_key).await;
    }

    #[tokio::test]
    async fn test_initial_account_state2() {
        let (_, public_key, _) = utils::testing_keys2();
        test_initial_account_state(public_key).await;
    }

    #[tokio::test]
    async fn test_initial_account_state3() {
        let (_, public_key, _) = utils::testing_keys3();
        test_initial_account_state(public_key).await;
    }

    async fn test_balance_at_first_version(public_key: Point) {
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let db = Db::new(clock, TEST_CHAIN_ID, testing_identity(), []).unwrap();
        let account_address = utils::public_key_to_wallet_address(public_key);
        let (block, proof) = db
            .get_account_info(account_address, default_genesis_block_hash())
            .await
            .unwrap();
        assert_eq!(block.hash(), default_genesis_block_hash());
        assert_eq!(proof.key(), account_address);
        assert_eq!(*proof.value(), AccountInfo::default());
    }

    #[tokio::test]
    async fn test_balance_at_first_version1() {
        let (_, public_key, _) = utils::testing_keys1();
        test_balance_at_first_version(public_key).await;
    }

    #[tokio::test]
    async fn test_balance_at_first_version2() {
        let (_, public_key, _) = utils::testing_keys2();
        test_balance_at_first_version(public_key).await;
    }

    #[tokio::test]
    async fn test_non_default_initial_account_state() {
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let (_, public_key1, _) = utils::testing_keys1();
        let account_address1 = utils::public_key_to_wallet_address(public_key1);
        let (_, public_key2, _) = utils::testing_keys2();
        let account_address2 = utils::public_key_to_wallet_address(public_key2);
        let (_, public_key3, _) = utils::testing_keys3();
        let account_address3 = utils::public_key_to_wallet_address(public_key3);
        let account = AccountInfo {
            last_nonce: 0,
            balance: Scalar::from(30),
            staking_balance: Scalar::from(100),
        };
        let db = Db::new(
            clock,
            TEST_CHAIN_ID,
            testing_identity(),
            [
                (account_address1, account),
                (account_address2, AccountInfo::with_balance(42.into())),
            ],
        )
        .unwrap();
        let block_hash = utils::parse_pallas_scalar(
            "0x27f5f8875564ea3039c1c2a672a01787ecb3e708ff0ffbd155f0565b35fda999",
        );
        let (block, proof) = db.get_latest_account_info(account_address1).await.unwrap();
        assert_eq!(block.hash(), block_hash);
        assert_eq!(proof.key(), account_address1);
        assert_eq!(*proof.value(), account);
        let (block, proof) = db.get_latest_account_info(account_address2).await.unwrap();
        assert_eq!(block.hash(), block_hash);
        assert_eq!(proof.key(), account_address2);
        assert_eq!(*proof.value(), AccountInfo::with_balance(42.into()));
        let (block, proof) = db.get_latest_account_info(account_address3).await.unwrap();
        assert_eq!(block.hash(), block_hash);
        assert_eq!(proof.key(), account_address3);
        assert_eq!(*proof.value(), AccountInfo::default());
    }

    #[tokio::test]
    async fn test_non_default_account_state_at_first_version() {
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let (_, public_key1, _) = utils::testing_keys1();
        let account_address1 = utils::public_key_to_wallet_address(public_key1);
        let (_, public_key2, _) = utils::testing_keys2();
        let account_address2 = utils::public_key_to_wallet_address(public_key2);
        let (_, public_key3, _) = utils::testing_keys3();
        let account_address3 = utils::public_key_to_wallet_address(public_key3);
        let account = AccountInfo {
            last_nonce: 0,
            balance: Scalar::from(30),
            staking_balance: Scalar::from(100),
        };
        let db = Db::new(
            clock,
            TEST_CHAIN_ID,
            testing_identity(),
            [
                (account_address1, account),
                (account_address2, AccountInfo::with_balance(42.into())),
            ],
        )
        .unwrap();
        let block_hash = utils::parse_pallas_scalar(
            "0x27f5f8875564ea3039c1c2a672a01787ecb3e708ff0ffbd155f0565b35fda999",
        );
        let (block, proof) = db
            .get_account_info(account_address1, block_hash)
            .await
            .unwrap();
        assert_eq!(block.hash(), block_hash);
        assert_eq!(proof.key(), account_address1);
        assert_eq!(*proof.value(), account);
        let (block, proof) = db
            .get_account_info(account_address2, block_hash)
            .await
            .unwrap();
        assert_eq!(block.hash(), block_hash);
        assert_eq!(proof.key(), account_address2);
        assert_eq!(*proof.value(), AccountInfo::with_balance(42.into()));
        let (block, proof) = db
            .get_account_info(account_address3, block_hash)
            .await
            .unwrap();
        assert_eq!(block.hash(), block_hash);
        assert_eq!(proof.key(), account_address3);
        assert_eq!(*proof.value(), AccountInfo::default());
    }

    #[tokio::test]
    async fn test_close_empty_block() {
        let (_, public_key1, _) = utils::testing_keys2();
        let address1 = utils::public_key_to_wallet_address(public_key1);
        let (_, public_key2, _) = utils::testing_keys3();
        let address2 = utils::public_key_to_wallet_address(public_key2);
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let db = Db::new(
            clock,
            TEST_CHAIN_ID,
            testing_identity(),
            [
                (address1, AccountInfo::with_balance(321.into())),
                (address2, AccountInfo::with_balance(100.into())),
            ],
        )
        .unwrap();
        let block_hash1 = db.get_latest_block().await.hash();
        let block_hash2 = utils::parse_pallas_scalar(
            "0x048aefa6cb901d8d75edc9648c6c540efcc037e5effbd0b369b22aacfd6665b7",
        );
        assert_ne!(block_hash1, block_hash2);
        assert_eq!(db.close_block().await.hash(), block_hash2);
        assert_eq!(db.current_version().await, 2);
        assert_ne!(block_hash1, block_hash2);
        let (_, proof) = db.get_account_info(address1, block_hash1).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(321.into()));
        let (_, proof) = db.get_account_info(address2, block_hash1).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(100.into()));
        let (_, proof) = db.get_account_info(address1, block_hash2).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(321.into()));
        let (_, proof) = db.get_account_info(address2, block_hash2).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(100.into()));
    }

    #[tokio::test]
    async fn test_add_transaction() {
        let (secret_key, public_key1, _) = utils::testing_keys2();
        let address1 = utils::public_key_to_wallet_address(public_key1);
        let key_manager = keys::KeyManager::new(secret_key);
        let (_, public_key2, _) = utils::testing_keys3();
        let address2 = utils::public_key_to_wallet_address(public_key2);
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let db = Db::new(
            clock,
            TEST_CHAIN_ID,
            testing_identity(),
            [
                (address1, AccountInfo::with_balance(321.into())),
                (address2, AccountInfo::with_balance(100.into())),
            ],
        )
        .unwrap();
        assert!(
            db.add_transaction(
                &Transaction::make_coin_transfer_proto(
                    &key_manager,
                    H256::from_slice(&[
                        1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0,
                    ]),
                    TEST_CHAIN_ID,
                    1,
                    address2,
                    123.into(),
                )
                .unwrap()
            )
            .await
            .is_ok()
        );
        let block_hash1 = db.get_latest_block().await.hash();
        let block_hash2 = utils::parse_pallas_scalar(
            "0x0230ccdd73f27af7c1b79abae35e9de76adc56beb6f2a0e1609a7bd82df9c3a2",
        );
        assert_ne!(block_hash1, block_hash2);
        assert_eq!(db.close_block().await.hash(), block_hash2);
        assert_eq!(db.current_version().await, 2);
        let (_, proof) = db.get_account_info(address1, block_hash1).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(321.into()));
        let (_, proof) = db.get_account_info(address2, block_hash1).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(100.into()));
        let (_, proof) = db.get_account_info(address1, block_hash2).await.unwrap();
        assert_eq!(
            *proof.value(),
            AccountInfo {
                last_nonce: 1,
                balance: 198.into(),
                staking_balance: Scalar::ZERO,
            }
        );
        let (_, proof) = db.get_account_info(address2, block_hash2).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(223.into()));
    }

    #[tokio::test]
    async fn test_add_two_transactions() {
        let (secret_key1, public_key1, _) = utils::testing_keys2();
        let address1 = utils::public_key_to_wallet_address(public_key1);
        let km1 = keys::KeyManager::new(secret_key1);
        let (secret_key2, public_key2, _) = utils::testing_keys3();
        let address2 = utils::public_key_to_wallet_address(public_key2);
        let km2 = keys::KeyManager::new(secret_key2);
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let db = Db::new(
            clock,
            TEST_CHAIN_ID,
            testing_identity(),
            [
                (address1, AccountInfo::with_balance(321.into())),
                (address2, AccountInfo::with_balance(100.into())),
            ],
        )
        .unwrap();
        let nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 0,
        ]);
        assert!(
            db.add_transaction(
                &Transaction::make_coin_transfer_proto(
                    &km1,
                    nonce,
                    TEST_CHAIN_ID,
                    1,
                    address2,
                    123.into(),
                )
                .unwrap()
            )
            .await
            .is_ok()
        );
        assert!(
            db.add_transaction(
                &Transaction::make_coin_transfer_proto(
                    &km2,
                    nonce,
                    TEST_CHAIN_ID,
                    1,
                    address1,
                    42.into(),
                )
                .unwrap()
            )
            .await
            .is_ok()
        );
        let block_hash1 = db.get_latest_block().await.hash();
        let block_hash2 = utils::parse_pallas_scalar(
            "0x156825c978a11fa86406aa9ea2be248b837613a033eb570bf10e23e0b4a6d031",
        );
        assert_eq!(db.close_block().await.hash(), block_hash2);
        assert_eq!(db.current_version().await, 2);
        let (_, proof) = db.get_account_info(address1, block_hash1).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(321.into()));
        let (_, proof) = db.get_account_info(address2, block_hash1).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(100.into()));
        let (_, proof) = db.get_account_info(address1, block_hash2).await.unwrap();
        assert_eq!(
            *proof.value(),
            AccountInfo {
                last_nonce: 1,
                balance: 240.into(),
                staking_balance: Scalar::ZERO,
            }
        );
        let (_, proof) = db.get_account_info(address2, block_hash2).await.unwrap();
        assert_eq!(
            *proof.value(),
            AccountInfo {
                last_nonce: 1,
                balance: 181.into(),
                staking_balance: Scalar::ZERO,
            }
        );
    }

    #[tokio::test]
    async fn test_reject_transaction_with_bad_chain_id() {
        let (secret_key, public_key1, _) = utils::testing_keys2();
        let address1 = utils::public_key_to_wallet_address(public_key1);
        let key_manager = keys::KeyManager::new(secret_key);
        let (_, public_key2, _) = utils::testing_keys3();
        let address2 = utils::public_key_to_wallet_address(public_key2);
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let db = Db::new(
            clock,
            TEST_CHAIN_ID,
            testing_identity(),
            [
                (address1, AccountInfo::with_balance(321.into())),
                (address2, AccountInfo::with_balance(100.into())),
            ],
        )
        .unwrap();
        assert!(
            db.add_transaction(
                &Transaction::make_coin_transfer_proto(
                    &key_manager,
                    H256::from_slice(&[
                        1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0,
                    ]),
                    TEST_CHAIN_ID + 1,
                    1,
                    address2,
                    123.into(),
                )
                .unwrap()
            )
            .await
            .is_err()
        );
        let block_hash1 = db.get_latest_block().await.hash();
        let block_hash2 = utils::parse_pallas_scalar(
            "0x048aefa6cb901d8d75edc9648c6c540efcc037e5effbd0b369b22aacfd6665b7",
        );
        assert_eq!(db.close_block().await.hash(), block_hash2);
        assert_eq!(db.current_version().await, 2);
        let (_, proof) = db.get_account_info(address1, block_hash1).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(321.into()));
        let (_, proof) = db.get_account_info(address2, block_hash1).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(100.into()));
        let (_, proof) = db.get_account_info(address1, block_hash2).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(321.into()));
        let (_, proof) = db.get_account_info(address2, block_hash2).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(100.into()));
    }

    #[tokio::test]
    async fn test_reject_transaction_with_invalid_nonce1() {
        let (secret_key, public_key1, _) = utils::testing_keys2();
        let address1 = utils::public_key_to_wallet_address(public_key1);
        let key_manager = keys::KeyManager::new(secret_key);
        let (_, public_key2, _) = utils::testing_keys3();
        let address2 = utils::public_key_to_wallet_address(public_key2);
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let db = Db::new(
            clock,
            TEST_CHAIN_ID,
            testing_identity(),
            [
                (address1, AccountInfo::with_balance(321.into())),
                (address2, AccountInfo::with_balance(100.into())),
            ],
        )
        .unwrap();
        let signature_nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 0,
        ]);
        assert!(
            db.add_transaction(
                &Transaction::make_coin_transfer_proto(
                    &key_manager,
                    signature_nonce,
                    TEST_CHAIN_ID,
                    10,
                    address2,
                    123.into(),
                )
                .unwrap()
            )
            .await
            .is_ok()
        );
        assert!(
            db.add_transaction(
                &Transaction::make_coin_transfer_proto(
                    &key_manager,
                    signature_nonce,
                    TEST_CHAIN_ID,
                    9,
                    address2,
                    123.into(),
                )
                .unwrap()
            )
            .await
            .is_err()
        );
        let block_hash1 = db.get_latest_block().await.hash();
        let block_hash2 = utils::parse_pallas_scalar(
            "0x2322760adbcb8e7ddcf7818993efef024100f077b2ca6255ef543730f381b248",
        );
        assert_eq!(db.close_block().await.hash(), block_hash2);
        assert_eq!(db.current_version().await, 2);
        let (_, proof) = db.get_account_info(address1, block_hash1).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(321.into()));
        let (_, proof) = db.get_account_info(address2, block_hash1).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(100.into()));
        let (_, proof) = db.get_account_info(address1, block_hash2).await.unwrap();
        assert_eq!(
            *proof.value(),
            AccountInfo {
                last_nonce: 10,
                balance: 198.into(),
                staking_balance: Scalar::ZERO,
            }
        );
        let (_, proof) = db.get_account_info(address2, block_hash2).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(223.into()));
    }

    #[tokio::test]
    async fn test_reject_transaction_with_invalid_nonce2() {
        let (secret_key, public_key1, _) = utils::testing_keys2();
        let address1 = utils::public_key_to_wallet_address(public_key1);
        let key_manager = keys::KeyManager::new(secret_key);
        let (_, public_key2, _) = utils::testing_keys3();
        let address2 = utils::public_key_to_wallet_address(public_key2);
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let db = Db::new(
            clock,
            TEST_CHAIN_ID,
            testing_identity(),
            [
                (address1, AccountInfo::with_balance(321.into())),
                (address2, AccountInfo::with_balance(100.into())),
            ],
        )
        .unwrap();
        let signature_nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 0,
        ]);
        assert!(
            db.add_transaction(
                &Transaction::make_coin_transfer_proto(
                    &key_manager,
                    signature_nonce,
                    TEST_CHAIN_ID,
                    10,
                    address2,
                    123.into(),
                )
                .unwrap()
            )
            .await
            .is_ok()
        );
        assert!(
            db.add_transaction(
                &Transaction::make_coin_transfer_proto(
                    &key_manager,
                    signature_nonce,
                    TEST_CHAIN_ID,
                    10,
                    address2,
                    123.into(),
                )
                .unwrap()
            )
            .await
            .is_err()
        );
        let block_hash1 = db.get_latest_block().await.hash();
        let block_hash2 = utils::parse_pallas_scalar(
            "0x2322760adbcb8e7ddcf7818993efef024100f077b2ca6255ef543730f381b248",
        );
        assert_eq!(db.close_block().await.hash(), block_hash2);
        assert_eq!(db.current_version().await, 2);
        let (_, proof) = db.get_account_info(address1, block_hash1).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(321.into()));
        let (_, proof) = db.get_account_info(address2, block_hash1).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(100.into()));
        let (_, proof) = db.get_account_info(address1, block_hash2).await.unwrap();
        assert_eq!(
            *proof.value(),
            AccountInfo {
                last_nonce: 10,
                balance: 198.into(),
                staking_balance: Scalar::ZERO
            }
        );
        let (_, proof) = db.get_account_info(address2, block_hash2).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(223.into()));
    }

    #[tokio::test]
    async fn test_new_transaction_with_valid_nonce() {
        let (secret_key, public_key1, _) = utils::testing_keys2();
        let address1 = utils::public_key_to_wallet_address(public_key1);
        let key_manager = keys::KeyManager::new(secret_key);
        let (_, public_key2, _) = utils::testing_keys3();
        let address2 = utils::public_key_to_wallet_address(public_key2);
        let clock = mock_clock(SystemTime::UNIX_EPOCH + Duration::from_secs(71104));
        let db = Db::new(
            clock,
            TEST_CHAIN_ID,
            testing_identity(),
            [
                (address1, AccountInfo::with_balance(321.into())),
                (address2, AccountInfo::with_balance(100.into())),
            ],
        )
        .unwrap();
        let signature_nonce = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 0,
        ]);
        assert!(
            db.add_transaction(
                &Transaction::make_coin_transfer_proto(
                    &key_manager,
                    signature_nonce,
                    TEST_CHAIN_ID,
                    10,
                    address2,
                    123.into(),
                )
                .unwrap()
            )
            .await
            .is_ok()
        );
        assert!(
            db.add_transaction(
                &Transaction::make_coin_transfer_proto(
                    &key_manager,
                    signature_nonce,
                    TEST_CHAIN_ID,
                    11,
                    address2,
                    123.into(),
                )
                .unwrap()
            )
            .await
            .is_ok()
        );
        let block_hash1 = db.get_latest_block().await.hash();
        let block_hash2 = utils::parse_pallas_scalar(
            "0x38531be56a9413ce0c3bd6870369bca4fa9413a5bdd185d1ef3569993eaf9031",
        );
        assert_eq!(db.close_block().await.hash(), block_hash2);
        assert_eq!(db.current_version().await, 2);
        let (_, proof) = db.get_account_info(address1, block_hash1).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(321.into()));
        let (_, proof) = db.get_account_info(address2, block_hash1).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(100.into()));
        let (_, proof) = db.get_account_info(address1, block_hash2).await.unwrap();
        assert_eq!(
            *proof.value(),
            AccountInfo {
                last_nonce: 11,
                balance: 75.into(),
                staking_balance: Scalar::ZERO
            }
        );
        let (_, proof) = db.get_account_info(address2, block_hash2).await.unwrap();
        assert_eq!(*proof.value(), AccountInfo::with_balance(346.into()));
    }

    // TODO
}
