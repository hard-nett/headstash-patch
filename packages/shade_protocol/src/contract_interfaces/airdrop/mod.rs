pub mod account;
pub mod claim_info;
pub mod errors;

use crate::{
    c_std::{Addr, Binary, Uint128},
    contract_interfaces::airdrop::account::{AccountPermit, AddressProofPermit},
    utils::{asset::Contract, generic_response::ResponseStatus},
};

use crate::utils::{ExecuteCallback, InstantiateCallback, Query};
use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct Config {
    pub admin: Addr,
    // Used for permit validation when querying
    pub contract: Addr,
    // Where the decayed tokens will be dumped, if none then nothing happens
    pub dump_address: Option<Addr>,
    // The snip20 to be minted
    pub airdrop_snip20: Contract,
    // An optional, second snip20 to be minted
    pub airdrop_snip20_optional: Contract,
    // Airdrop amount
    pub airdrop_amount: Uint128,
    // Required tasks
    // pub task_claim: Vec<RequiredTask>,
    // Checks if airdrop has started / ended
    pub start_date: u64,
    // Airdrop stops at end date if there is one
    pub end_date: Option<u64>,
    // Starts to decay at this date
    pub decay_start: Option<u64>,
    // This is necessary to validate the airdrop information
    // tree root
    pub merkle_root: String,
    // tree height
    pub total_accounts: u32,
    // {wallet}
    pub claim_msg_plaintext: String,
    // Protects from leaking user information by limiting amount detail
}

#[cw_serde]
pub struct InstantiateMsg {
    pub admin: Option<Addr>,
    // Where the decayed tokens will be dumped, if none then nothing happens
    pub dump_address: Option<Addr>,
    // primary scrt-20 contract being distributed
    pub airdrop_token: Contract,
    // an optional, second snip20 to be minted
    pub airdrop_2: Contract,
    // total amount of airdrop
    pub airdrop_amount: Uint128,
    // The airdrop time limit
    pub start_date: Option<u64>,
    // Can be set to never end
    pub end_date: Option<u64>,
    // Starts to decay at this date
    pub decay_start: Option<u64>,
    // Base64 encoded version of the tree root
    pub merkle_root: String,
    // Root height
    pub total_accounts: u32,
    /// {wallet}
    pub claim_msg_plaintext: String,
    // Protects from leaking user information by limiting amount detail
}

impl InstantiateCallback for InstantiateMsg {
    const BLOCK_SIZE: usize = 256;
}

#[cw_serde]
pub enum ExecuteMsg {
    UpdateConfig {
        admin: Option<Addr>,
        dump_address: Option<Addr>,
        start_date: Option<u64>,
        end_date: Option<u64>,
        decay_start: Option<u64>,
        padding: Option<String>,
    },
    /// * creates or updates an account. 
    /// * use msg.sender addr as key to search if an account exist.
    /// * Stores an unverified eth_pubkey that will be used to verify
    ///   ownership of eth_sig provided when claiming headstash. 
    /// * 
    Account {
        eth_pubkey: String,
        amount: Option<Uint128>,
        addresses: Vec<AddressProofPermit>,
        padding: Option<String>,
    },
    DisablePermitKey {
        key: String,
        padding: Option<String>,
    },
    SetViewingKey {
        key: String,
        padding: Option<String>,
    },
    Claim {
        amount: Uint128,
        eth_pubkey: String,
        eth_sig: String,
        proof: Vec<String>,
        padding: Option<String>,
    },
    ClaimDecay {
        padding: Option<String>,
    },
}

impl ExecuteCallback for ExecuteMsg {
    const BLOCK_SIZE: usize = 256;
}

#[cw_serde]
pub enum ExecuteAnswer {
    UpdateConfig {
        status: ResponseStatus,
    },
    Account {
        status: ResponseStatus,
        addresses: Vec<Addr>,
        eth_pubkey: String,
        claimed: bool,
    },
    DisablePermitKey {
        status: ResponseStatus,
    },
    SetViewingKey {
        status: ResponseStatus,
    },
    Claim {
        status: ResponseStatus,
        claimed: bool,
        addresses: Vec<Addr>,
        eth_pubkey: String,
    },
    ClaimDecay {
        status: ResponseStatus,
    },
    CreateViewingKey { key: String },
}

#[cw_serde]
pub enum QueryMsg {
    Config {},
    Dates {
        current_date: Option<u64>,
    },
    TotalClaimed {},
    Account {
        permit: AccountPermit,
        eth_pubkey: String,
    },
    AccountWithKey {
        account: Addr,
        key: String,
        eth_pubkey: String,
    },
}

impl Query for QueryMsg {
    const BLOCK_SIZE: usize = 256;
}

#[cw_serde]
pub enum QueryAnswer {
    Config {
        config: Config,
    },
    Dates {
        start: u64,
        end: Option<u64>,
    },
    TotalClaimed {
        claimed: Uint128,
    },
    Account {
        claimed: bool,
        addresses: Vec<Addr>,
        eth_pubkey: String,
    },
}

#[cw_serde]
pub struct AccountVerification {
    pub eth_pubkey: String,
    pub account: Addr,
    pub claimed: bool,
}
