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
use cosmwasm_std::ContractInfo;

#[cw_serde]
pub struct Config {
    pub snip20_1: Contract,
    pub snip20_2: Option<ContractInfo>,
    pub merkle_root: Binary,
    pub viewing_key: String,
    pub claim_msg_plaintext: String,
    pub admin: Option<Addr>,
}

#[cw_serde]
pub struct InstantiateMsg {
    pub snip20_1: Contract,
    pub snip20_2: Option<ContractInfo>,
    pub merkle_root: Binary,
    pub viewing_key: String,
    pub total_amount: Uint128,
    pub claim_msg_plaintext: String,
    pub admin: Option<Addr>,
}

impl InstantiateCallback for InstantiateMsg {
    const BLOCK_SIZE: usize = 256;
}

#[cw_serde]
pub enum ExecuteMsg {
    Claim {
        amount: Uint128,
        eth_pubkey: String,
        eth_sig: String,
        proof: Vec<String>,
    },
    Clawback {},
}

impl ExecuteCallback for ExecuteMsg {
    const BLOCK_SIZE: usize = 256;
}

#[cw_serde]
pub enum ExecuteAnswer {
    UpdateConfig {
        status: ResponseStatus,
    },
    // AddTask {
    //     status: ResponseStatus,
    // },
    // CompleteTask {
    //     status: ResponseStatus,
    // },
    // Account {
    //     status: ResponseStatus,
    //     // Total eligible
    //     total: Uint128,
    //     // Total claimed
    //     claimed: Uint128,
    //     // finished_tasks: Vec<RequiredTask>,
    //     // Addresses claimed
    //     addresses: Vec<Addr>,
    //     eth_pubkey: String,
    //     eth_sig: String,
    // },
    DisablePermitKey {
        status: ResponseStatus,
    },
    SetViewingKey {
        status: ResponseStatus,
    },
    Claim {
        status: ResponseStatus,
        // Total eligible
        // total: Uint128,
        // Total claimed
        claimed: Uint128,
        // finished_tasks: Vec<RequiredTask>,
        // Addresses claimed
        // addresses: Vec<Addr>,
        address: String,
        eth_pubkey: String,
        eth_sig: String,
    },
    ClaimDecay {
        status: ResponseStatus,
    },
}

#[cw_serde]
pub enum QueryMsg {
    Config {},
}

impl Query for QueryMsg {
    const BLOCK_SIZE: usize = 256;
}

#[cw_serde]
pub enum QueryAnswer {
    HeadstashConfigResponse {
        config: Config,
    },
}

#[cw_serde]
pub struct AccountVerification {
    // pub eth_pubkey: String,
    pub account: Addr,
    pub claimed: bool,
}
