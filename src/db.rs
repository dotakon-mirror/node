use anyhow::{Result, anyhow};
use primitive_types::U256;
use std::collections::BTreeMap;
use std::fs::File;

trait AbstractAccountData {
    /// The first component of each element is the version number (aka the block number); the second
    /// one is the balance at that revision.
    fn balance_history(&self) -> &[(usize, U256)];
}

struct PublicAccountData {
    balance_history: Vec<(usize, U256)>,
}

impl AbstractAccountData for PublicAccountData {
    fn balance_history(&self) -> &[(usize, U256)] {
        self.balance_history.as_slice()
    }
}

struct SmartContractData {
    balance_history: Vec<(usize, U256)>,
    memory: BTreeMap<u64, u64>,
}

impl AbstractAccountData for SmartContractData {
    fn balance_history(&self) -> &[(usize, U256)] {
        self.balance_history.as_slice()
    }
}

enum AccountData {
    PublicAccount(PublicAccountData),
    SmartContract(SmartContractData),
}

pub struct Db {
    file: File,
    current_version: usize,
    account_data: BTreeMap<U256, AccountData>,
}

impl Db {
    pub fn new(file: File) -> Self {
        Self {
            file,
            current_version: 0,
            account_data: BTreeMap::new(),
        }
    }

    pub fn current_version(&self) -> usize {
        self.current_version
    }

    fn get_account_balance<A: AbstractAccountData>(account: &A, version: usize) -> U256 {
        let history = account.balance_history();
        match history.binary_search_by_key(&version, |&(version, _)| version) {
            Ok(index) => {
                let (_, balance) = history[index];
                balance
            }
            Err(index) => {
                if index > 0 {
                    let (_, balance) = history[index - 1];
                    balance
                } else {
                    U256::zero()
                }
            }
        }
    }

    pub fn get_balance(&self, account_address: U256, version: usize) -> Result<U256> {
        if version > self.current_version {
            return Err(anyhow!("invalid version number: {}", version));
        }
        Ok(match self.account_data.get(&account_address) {
            Some(data) => match data {
                AccountData::PublicAccount(data) => Self::get_account_balance(data, version),
                AccountData::SmartContract(data) => Self::get_account_balance(data, version),
            },
            None => U256::zero(),
        })
    }

    fn get_latest_account_balance<A: AbstractAccountData>(account: &A) -> (usize, U256) {
        let history = account.balance_history();
        if history.len() > 0 {
            history[history.len() - 1]
        } else {
            (0, U256::zero())
        }
    }

    pub fn get_latest_balance(&self, account_address: U256) -> (usize, U256) {
        match self.account_data.get(&account_address) {
            Some(data) => match data {
                AccountData::PublicAccount(data) => Self::get_latest_account_balance(data),
                AccountData::SmartContract(data) => Self::get_latest_account_balance(data),
            },
            None => (0, U256::zero()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;
    use tempfile::tempfile;

    #[test]
    fn test_initial_version() {
        let db = Db::new(tempfile().unwrap());
        assert_eq!(db.current_version(), 0);
    }

    fn test_initial_balance(public_key: U256) {
        let db = Db::new(tempfile().unwrap());
        let (version, balance) =
            db.get_latest_balance(utils::public_key_to_wallet_address(public_key));
        assert_eq!(version, 0);
        assert_eq!(balance, U256::zero());
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

    fn test_balance_at_initial_revision(public_key: U256) {
        let db = Db::new(tempfile().unwrap());
        assert_eq!(db.current_version(), 0);
        assert_eq!(
            db.get_balance(utils::public_key_to_wallet_address(public_key), 0)
                .unwrap(),
            U256::zero()
        );
        assert!(
            !db.get_balance(utils::public_key_to_wallet_address(public_key), 1)
                .is_ok()
        );
    }

    #[test]
    fn test_balance_at_initial_revision1() {
        let (_, public_key, _) = utils::testing_keys1();
        test_balance_at_initial_revision(public_key);
    }

    #[test]
    fn test_balance_at_initial_revision2() {
        let (_, public_key, _) = utils::testing_keys2();
        test_balance_at_initial_revision(public_key);
    }

    // TODO
}
