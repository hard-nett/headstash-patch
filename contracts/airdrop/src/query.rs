use crate::{
    handle::decay_factor,
    state::{
        account_r, account_viewkey_r, config_r, decay_claimed_r, eth_pubkey_claim_r, total_claimed_r, validate_account_permit
    },
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
        decay_start: config.decay_start,
        decay_factor: current_date.map(|date| Uint128::new(100u128) * decay_factor(date, &config)),
    })
}

pub fn total_claimed(deps: Deps) -> StdResult<QueryAnswer> {
    let claimed: Uint128;
    let total_claimed = total_claimed_r(deps.storage).load()?;
    if decay_claimed_r(deps.storage).load()? {
        claimed = total_claimed;
    } else {
        let config = config_r(deps.storage).load()?;
        claimed = total_claimed.checked_div(config.query_rounding)? * config.query_rounding;
    }
    Ok(QueryAnswer::TotalClaimed { claimed })
}

fn account_information(
    deps: Deps,
    account_address: Addr,
    current_date: Option<u64>,
) -> StdResult<QueryAnswer> {
    let account = account_r(deps.storage).load(account_address.to_string().as_bytes())?;

    // Calculate eligible tasks
    let config = config_r(deps.storage).load()?;

    // Check if eth address has claimed
    let claim_state = eth_pubkey_claim_r(deps.storage).may_load(account.eth_pubkey.as_bytes())?;

    Ok(QueryAnswer::Account {
        claimed: claim_state.unwrap(),
        addresses: account.addresses,
        eth_pubkey: account.eth_pubkey,
    })
}

pub fn account(
    deps: Deps,
    permit: AccountPermit,
    current_date: Option<u64>,
) -> StdResult<QueryAnswer> {
    let config = config_r(deps.storage).load()?;
    account_information(
        deps,
        validate_account_permit(deps, &permit, config.contract)?,
        current_date,
    )
}

pub fn account_with_key(
    deps: Deps,
    account: Addr,
    key: String,
    current_date: Option<u64>,
) -> StdResult<QueryAnswer> {
    // Validate address
    let stored_hash = account_viewkey_r(deps.storage).load(account.to_string().as_bytes())?;

    if !AccountKey(key).compare(&stored_hash) {
        return Err(invalid_viewing_key());
    }

    account_information(deps, account, current_date)
}
