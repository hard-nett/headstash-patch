use crate::state::{
    account_r,
    // account_total_claimed_r,
    account_viewkey_r,
    claim_status_r,
    config_r,
    decay_claimed_r,
    eth_pubkey_claim_r,
    total_claimed_r,
    validate_account_permit,
};
use shade_protocol::{
    airdrop::{
        account::{AccountKey, AccountPermit},
        errors::invalid_viewing_key,
        QueryAnswer,
    },
    c_std::{Addr, Deps, StdResult, Uint128},
    query_authentication::viewing_keys::ViewingKey,
};

pub fn config(deps: Deps) -> StdResult<QueryAnswer> {
    Ok(QueryAnswer::Config {
        config: config_r(deps.storage).load()?,
    })
}

pub fn dates(deps: Deps, current_date: Option<u64>) -> StdResult<QueryAnswer> {
    let config = config_r(deps.storage).load()?;
    Ok(QueryAnswer::Dates {
        start: config.start_date,
        end: config.end_date,
    })
}

pub fn total_claimed(deps: Deps) -> StdResult<QueryAnswer> {
    let claimed: Uint128;
    let total_claimed = total_claimed_r(deps.storage).load()?;

    claimed = total_claimed;
    Ok(QueryAnswer::TotalClaimed { claimed })
}

// returns account information for an eth_pubkey
fn account_information(
    deps: Deps,
    account_address: Addr,
    eth_pubkey: String,
) -> StdResult<QueryAnswer> {
    let account = account_r(deps.storage).load(account_address.to_string().as_bytes())?;

    // Check if eth address has claimed
    let claim_state = eth_pubkey_claim_r(deps.storage).may_load(account.eth_pubkey.as_bytes())?;

    Ok(QueryAnswer::Account {
        claimed: claim_state.unwrap(),
        addresses: account.addresses,
        eth_pubkey: account.eth_pubkey,
    })
}

pub fn account(deps: Deps, permit: AccountPermit, eth_pubkey: String) -> StdResult<QueryAnswer> {
    let config = config_r(deps.storage).load()?;
    account_information(
        deps,
        validate_account_permit(deps, &permit, config.contract)?,
        eth_pubkey,
    )
}

pub fn account_with_key(
    deps: Deps,
    account: Addr,
    key: String,
    eth_pubkey: String,
) -> StdResult<QueryAnswer> {
    // Validate address
    let stored_hash = account_viewkey_r(deps.storage).load(account.to_string().as_bytes())?;

    if !AccountKey(key).compare(&stored_hash) {
        return Err(invalid_viewing_key());
    }

    account_information(deps, account, eth_pubkey)
}
