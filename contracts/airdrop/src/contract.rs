use crate::{
    handle::{
        try_account, try_claim, try_create_viewing_key, try_disable_permit_key, try_set_viewing_key, try_update_config
    },
    query,
    state::{config_w, decay_claimed_w, total_claimed_w},
};
use shade_protocol::{
    airdrop::{errors::invalid_dates, Config, ExecuteMsg, InstantiateMsg, QueryMsg},
    c_std::{
        shd_entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError,
        StdResult, Uint128,
    },
    utils::{pad_handle_result, pad_query_result},
};

// Used to pad up responses for better privacy.
pub const RESPONSE_BLOCK_SIZE: usize = 256;

#[shd_entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let start_date = match msg.start_date {
        None => env.block.time.seconds(),
        Some(date) => date,
    };

    if let Some(end_date) = msg.end_date {
        if end_date < start_date {
            return Err(invalid_dates(
                "EndDate",
                end_date.to_string().as_str(),
                "before",
                "StartDate",
                start_date.to_string().as_str(),
            ));
        }
    }

    // Avoid decay collisions
    if let Some(start_decay) = msg.decay_start {
        if start_decay < start_date {
            return Err(invalid_dates(
                "Decay",
                start_decay.to_string().as_str(),
                "before",
                "StartDate",
                start_date.to_string().as_str(),
            ));
        }
        if let Some(end_date) = msg.end_date {
            if start_decay > end_date {
                return Err(invalid_dates(
                    "EndDate",
                    end_date.to_string().as_str(),
                    "before",
                    "Decay",
                    start_decay.to_string().as_str(),
                ));
            }
        } else {
            return Err(StdError::generic_err("Decay must have an end date"));
        }
    }

    let config = Config {
        admin: msg.admin.unwrap_or(info.sender),
        contract: env.contract.address,
        dump_address: msg.dump_address,
        airdrop_snip20: msg.airdrop_token.clone(),
        airdrop_snip20_optional: msg.airdrop_snip20_optional.clone(),
        airdrop_amount: msg.airdrop_amount,
        start_date,
        end_date: msg.end_date,
        decay_start: msg.decay_start,
        merkle_root: msg.merkle_root,
        total_accounts: msg.total_accounts,
        claim_msg_plaintext: msg.claim_msg_plaintext,
    };

    config_w(deps.storage).save(&config)?;

    // Initialize claim amount
    total_claimed_w(deps.storage).save(&Uint128::zero())?;

    // clawback function??
    decay_claimed_w(deps.storage).save(&false)?;

    Ok(Response::new())
}

#[shd_entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    pad_handle_result(
        match msg {
            ExecuteMsg::UpdateConfig {
                admin,
                dump_address,
                start_date,
                end_date,
                ..
            } => try_update_config(
                deps,
                env,
                &info,
                admin,
                dump_address,
                start_date,
                end_date,
            ),
            ExecuteMsg::Account {
                eth_pubkey,
                addresses,
                ..
            } => try_account(
                deps,
                &env,
                &info,
                eth_pubkey,
                addresses,
            ),
            ExecuteMsg::DisablePermitKey { key, .. } => {
                try_disable_permit_key(deps, &env, &info, key)
            }
            ExecuteMsg::SetViewingKey { key, .. } => try_set_viewing_key(deps, &env, &info, key),
            ExecuteMsg::Claim {
                amount,
                eth_pubkey,
                eth_sig,
                proof,
                ..
            } => try_claim(deps, &env, &info, amount, eth_pubkey, eth_sig, proof),
            ExecuteMsg::ClaimDecay { .. } => crate::handle::try_claim_decay(deps, &env, &info),
        },
        RESPONSE_BLOCK_SIZE,
    )
}

#[shd_entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    pad_query_result(
        match msg {
            QueryMsg::Config {} => to_binary(&query::config(deps)?),
            QueryMsg::Dates { current_date } => to_binary(&query::dates(deps, current_date)?),
            QueryMsg::TotalClaimed {} => to_binary(&query::total_claimed(deps)?),
            QueryMsg::Account { permit, eth_pubkey } => {
                to_binary(&query::account(deps, permit, eth_pubkey)?)
            }
            QueryMsg::AccountWithKey {
                account,
                key,
                eth_pubkey,
            } => to_binary(&query::account_with_key(deps, account, key, eth_pubkey)?),
        },
        RESPONSE_BLOCK_SIZE,
    )
}
