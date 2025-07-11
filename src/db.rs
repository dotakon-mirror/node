use crate::dotakon;
use crate::mpt;
use crate::proto;
use anyhow::{Context, Result, anyhow};
use primitive_types::{H256, U256};
use sha3::{self, Digest};
use std::collections::BTreeMap;

const ACCOUNT_ADDRESS_KEY_LENGTH: usize = 32;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    hash: H256,
    number: u64,
    previous_block_hash: H256,
    account_balances_root_hash: H256,
}

impl BlockInfo {
    fn hash_block(
        block_number: u64,
        previous_block_hash: H256,
        account_balances_root_hash: H256,
    ) -> H256 {
        const DOMAIN_SEPARATOR: &str = "dotakon/block-hash-v1.0.0";
        let message = format!(
            "{{domain=\"{}\",number={},previous={:#x},balances={:#x}}}",
            DOMAIN_SEPARATOR, block_number, previous_block_hash, account_balances_root_hash
        );
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(message.as_bytes());
        H256::from_slice(hasher.finalize().as_slice())
    }

    fn new(block_number: u64, previous_block_hash: H256, account_balances_root_hash: H256) -> Self {
        Self {
            hash: Self::hash_block(
                block_number,
                previous_block_hash,
                account_balances_root_hash,
            ),
            number: block_number,
            previous_block_hash,
            account_balances_root_hash,
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

    pub fn account_balances_root_hash(&self) -> H256 {
        self.account_balances_root_hash
    }

    pub fn encode(&self) -> dotakon::BlockDescriptor {
        dotakon::BlockDescriptor {
            block_hash: Some(proto::h256_to_bytes32(self.hash)),
            block_number: Some(self.number),
            previous_block_hash: Some(proto::h256_to_bytes32(self.previous_block_hash)),
            account_balances_root_hash: Some(proto::h256_to_bytes32(
                self.account_balances_root_hash,
            )),
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
        let account_balances_root_hash = proto::h256_from_bytes32(
            &proto
                .account_balances_root_hash
                .context("account balance root hash field is missing")?,
        );
        let block_info = Self::new(
            block_number,
            previous_block_hash,
            account_balances_root_hash,
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
    fn value(&self) -> U256 {
        self.value
    }
}

impl From<U256> for AccountBalance {
    fn from(value: U256) -> Self {
        Self { value }
    }
}

impl Into<U256> for AccountBalance {
    fn into(self) -> U256 {
        self.value
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

type AccountBalances = mpt::MPT<AccountBalance, ACCOUNT_ADDRESS_KEY_LENGTH>;
pub type AccountBalanceProof = mpt::Proof<AccountBalance, ACCOUNT_ADDRESS_KEY_LENGTH>;

fn make_genesis_block() -> BlockInfo {
    let block_number = 0;
    let previous_block_hash = H256::zero();
    let account_balances_root_hash = AccountBalances::new().root_hash(block_number);
    BlockInfo::new(
        block_number,
        previous_block_hash,
        account_balances_root_hash,
    )
}

pub struct Db {
    blocks: Vec<BlockInfo>,
    block_numbers_by_hash: BTreeMap<H256, usize>,
    account_balances: AccountBalances,
}

impl Db {
    pub fn new() -> Self {
        let genesis_block = make_genesis_block();
        Self {
            blocks: vec![genesis_block],
            block_numbers_by_hash: BTreeMap::from([(genesis_block.hash, 0)]),
            account_balances: AccountBalances::new(),
        }
    }

    pub fn current_version(&self) -> usize {
        self.blocks.len()
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
        &self.blocks[0]
    }

    pub fn get_balance(
        &self,
        account_address: U256,
        block_hash: H256,
    ) -> Result<(BlockInfo, AccountBalanceProof)> {
        if let Some(block) = self.get_block_by_hash(block_hash) {
            Ok((
                *block,
                self.account_balances
                    .get_proof(&account_address.to_big_endian(), block.number)?,
            ))
        } else {
            Err(anyhow!("block not found"))
        }
    }

    pub fn get_latest_balance(
        &self,
        account_address: U256,
    ) -> Result<(BlockInfo, AccountBalanceProof)> {
        let block = self.get_latest_block();
        Ok((
            *block,
            self.account_balances
                .get_proof(&account_address.to_big_endian(), block.number)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mpt::{Proto, Sha3Hash},
        utils,
    };

    fn genesis_block_hash() -> H256 {
        "0x4fd6622a108075aaf8752956401a8680541ce20d8102904a359a7b033fca3df7"
            .parse()
            .unwrap()
    }

    #[test]
    fn test_block_info() {
        let previous_block_hash = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        let account_balances_root_hash = H256::from_slice(&[
            32u8, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
            11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
        ]);
        let block = BlockInfo::new(42, previous_block_hash, account_balances_root_hash);
        assert_ne!(block, make_genesis_block());
        assert_eq!(
            block.hash(),
            "0x2ebfadc5586917a6d539afc7bbbacc364a5243491420dae5e3d4b2a4d0dd133e"
                .parse()
                .unwrap()
        );
        assert_eq!(block.number(), 42);
        assert_eq!(block.previous_block_hash(), previous_block_hash);
        assert_eq!(
            block.account_balances_root_hash(),
            account_balances_root_hash
        );
        assert_eq!(BlockInfo::decode(&block.encode()).unwrap(), block);
    }

    #[test]
    fn test_genesis_block() {
        let block = make_genesis_block();
        assert_eq!(block.hash(), genesis_block_hash());
        assert_eq!(block.number(), 0);
        assert_eq!(block.previous_block_hash(), H256::zero());
        assert_eq!(
            block.account_balances_root_hash(),
            "0xb4a3716bd9261f312ea71656dda4caa0d694f0f6816712036ee8fce833e4b46f"
                .parse()
                .unwrap()
        );
        assert_eq!(BlockInfo::decode(&block.encode()).unwrap(), block);
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
        let db = Db::new();
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
    }

    fn test_initial_balance(public_key: U256) {
        let db = Db::new();
        let account_address = utils::public_key_to_wallet_address(public_key);
        let (block, proof) = db.get_latest_balance(account_address).unwrap();
        assert_eq!(block.hash(), genesis_block_hash());
        assert_eq!(U256::from_big_endian(proof.key()), account_address);
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

    fn test_balance_at_first_block(public_key: U256) {
        let db = Db::new();
        let account_address = utils::public_key_to_wallet_address(public_key);
        let (block, proof) = db
            .get_balance(account_address, genesis_block_hash())
            .unwrap();
        assert_eq!(block.hash(), genesis_block_hash());
        assert_eq!(U256::from_big_endian(proof.key()), account_address);
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
