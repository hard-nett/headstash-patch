use shade_protocol::c_std::Storage;
use shade_protocol::c_std::Uint128;
use shade_protocol::contract_interfaces::airdrop::Config;
use shade_protocol::storage::{
    bucket, bucket_read, singleton, singleton_read, Bucket, ReadonlyBucket, ReadonlySingleton,
    Singleton,
};

pub static CONFIG_KEY: &[u8] = b"config";
pub static ETH_PUBKEY_CLAIMED_KEY: &[u8] = b"eth_pubkey_claimed";
pub static TOTAL_CLAIMED_KEY: &[u8] = b"total_claimed";

pub fn config_w(storage: &mut dyn Storage) -> Singleton<Config> {
    singleton(storage, CONFIG_KEY)
}

pub fn config_r(storage: &dyn Storage) -> ReadonlySingleton<Config> {
    singleton_read(storage, CONFIG_KEY)
}

// Total claimed
pub fn total_claimed_r(storage: &dyn Storage) -> ReadonlySingleton<Uint128> {
    singleton_read(storage, TOTAL_CLAIMED_KEY)
}

pub fn total_claimed_w(storage: &mut dyn Storage) -> Singleton<Uint128> {
    singleton(storage, TOTAL_CLAIMED_KEY)
}

// If not found then its unrewarded; if true then claimed
pub fn claim_status_r(storage: &dyn Storage) -> ReadonlyBucket<bool> {
    bucket_read(storage, ETH_PUBKEY_CLAIMED_KEY)
}

pub fn claim_status_w(storage: &mut dyn Storage) -> Bucket<bool> {
    bucket(storage, ETH_PUBKEY_CLAIMED_KEY)
}
