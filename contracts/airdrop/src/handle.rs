use crate::state::{
    account_r, account_viewkey_w, account_w, address_in_account_w, claim_status_w, config_r,
    config_w, decay_claimed_w, eth_pubkey_claim_r, eth_pubkey_claim_w, revoke_permit,
    total_claimed_r, total_claimed_w, validate_address_permit,
};
use hex::decode_to_slice;
// use rs_merkle::{algorithms::Sha256, Hasher, MerkleProof};
use sha2::Digest;
use shade_protocol::{
    airdrop::{
        account::{Account, AccountKey, AddressProofMsg, AddressProofPermit},
        errors::{
            address_already_in_account, airdrop_ended, airdrop_not_started, already_claimed,
            claim_too_high, decay_claimed, decay_not_set, expected_memo, failed_verification,
            invalid_dates, not_admin, nothing_to_claim, wrong_length,
        },
        Config, ExecuteAnswer,
    },
    c_std::{
        ensure_eq, from_binary, to_binary, Addr, Api, Binary, Decimal, DepsMut, Env, MessageInfo,
        Response, StdResult, Storage, Uint128,
    },
    query_authentication::viewing_keys::ViewingKey,
    snip20::helpers::send_msg,
    utils::generic_response::ResponseStatus::{self, Success},
};
use std::{convert::TryInto, fmt::Write};

#[allow(clippy::too_many_arguments)]
pub fn try_update_config(
    deps: DepsMut,
    _env: Env,
    info: &MessageInfo,
    admin: Option<Addr>,
    dump_address: Option<Addr>,
    query_rounding: Option<Uint128>,
    start_date: Option<u64>,
    end_date: Option<u64>,
    decay_start: Option<u64>,
) -> StdResult<Response> {
    let config = config_r(deps.storage).load()?;
    // Check if admin
    if info.sender != config.admin {
        return Err(not_admin(config.admin.as_str()));
    }

    // Save new info
    let mut config = config_w(deps.storage);
    config.update(|mut state| {
        if let Some(admin) = admin {
            state.admin = admin;
        }
        if let Some(dump_address) = dump_address {
            state.dump_address = Some(dump_address);
        }
        if let Some(query_rounding) = query_rounding {
            state.query_rounding = query_rounding;
        }
        if let Some(start_date) = start_date {
            // Avoid date collisions
            if let Some(end_date) = end_date {
                if start_date > end_date {
                    return Err(invalid_dates(
                        "EndDate",
                        end_date.to_string().as_str(),
                        "before",
                        "StartDate",
                        start_date.to_string().as_str(),
                    ));
                }
            } else if let Some(end_date) = state.end_date {
                if start_date > end_date {
                    return Err(invalid_dates(
                        "EndDate",
                        end_date.to_string().as_str(),
                        "before",
                        "StartDate",
                        start_date.to_string().as_str(),
                    ));
                }
            }
            if let Some(start_decay) = decay_start {
                if start_date > start_decay {
                    return Err(invalid_dates(
                        "Decay",
                        start_decay.to_string().as_str(),
                        "before",
                        "StartDate",
                        start_date.to_string().as_str(),
                    ));
                }
            } else if let Some(start_decay) = state.decay_start {
                if start_date > start_decay {
                    return Err(invalid_dates(
                        "Decay",
                        start_decay.to_string().as_str(),
                        "before",
                        "StartDate",
                        start_date.to_string().as_str(),
                    ));
                }
            }

            state.start_date = start_date;
        }
        if let Some(end_date) = end_date {
            // Avoid date collisions
            if let Some(decay_start) = decay_start {
                if decay_start > end_date {
                    return Err(invalid_dates(
                        "EndDate",
                        end_date.to_string().as_str(),
                        "before",
                        "Decay",
                        decay_start.to_string().as_str(),
                    ));
                }
            } else if let Some(decay_start) = state.decay_start {
                if decay_start > end_date {
                    return Err(invalid_dates(
                        "EndDate",
                        end_date.to_string().as_str(),
                        "before",
                        "Decay",
                        decay_start.to_string().as_str(),
                    ));
                }
            }

            state.end_date = Some(end_date);
        }
        if decay_start.is_some() {
            state.decay_start = decay_start
        }

        Ok(state)
    })?;
    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::UpdateConfig { status: Success })?))
}

pub fn try_account(
    deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    addresses: Vec<AddressProofPermit>,
    eth_pubkey: String,
) -> StdResult<Response> {
    // Check if airdrop active
    let config = config_r(deps.storage).load()?;

    // Check that airdrop hasn't ended
    available(&config, env)?;

    // Setup account
    let sender = info.sender.to_string();

    // These variables are setup to facilitate updating
    let updating_account: bool;

    let mut account = match account_r(deps.storage).may_load(sender.as_bytes())? {
        None => {
            updating_account = false;
            let mut account = Account::default();

            // Validate permits
            try_add_account_addresses(
                deps.storage,
                deps.api,
                &config,
                &info.sender,
                &mut account,
                addresses.clone(),
                eth_pubkey.clone(),
            )?;

            // we setup an unchecked eth_pubkey for now. We will verify this eth_pubkey during
            // the claim msg, and will update to verified eth_pubkey.
            // sets the accounts eth_pubkey claim status to false. note we always check claim function when checking
            // the signed msg with the stored address, never both or isolated;
            // (to avoid contract panic, sender.clone is required for reading the account details,
            // prevents ability to determine if a eth_pubkey not yours has claimed)*
            claim_status_w(deps.storage, 0).save(sender.as_bytes(), &false)?;

            account
        }
        Some(acc) => {
            updating_account = true;
            acc
        }
    };

    // Update account after claim to calculate difference
    if updating_account {
        // Validate permits
        try_add_account_addresses(
            deps.storage,
            deps.api,
            &config,
            &info.sender,
            &mut account,
            addresses.clone(),
            eth_pubkey.clone(),
        )?;
    }

    // Save account
    account_w(deps.storage).save(sender.as_bytes(), &account)?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::Account {
        status: ResponseStatus::Success,
        claimed: eth_pubkey_claim_r(deps.storage)
            .load(account.eth_pubkey.to_string().as_bytes())?, // Will always be 0 since rewards are automatically claimed here
        addresses: account.addresses,
        eth_pubkey: account.eth_pubkey,
    })?))
}

pub fn try_disable_permit_key(
    deps: DepsMut,
    _env: &Env,
    info: &MessageInfo,
    key: String,
) -> StdResult<Response> {
    revoke_permit(deps.storage, info.sender.to_string(), key);

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::DisablePermitKey {
            status: Success,
        })?),
    )
}

pub fn try_set_viewing_key(
    deps: DepsMut,
    _env: &Env,
    info: &MessageInfo,
    key: String,
) -> StdResult<Response> {
    account_viewkey_w(deps.storage)
        .save(&info.sender.to_string().as_bytes(), &AccountKey(key).hash())?;

    Ok(
        Response::new().set_data(to_binary(&ExecuteAnswer::SetViewingKey {
            status: Success,
        })?),
    )
}

pub fn try_claim(
    deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    amount: Uint128,
    eth_pubkey: String,
    eth_sig: String,
    proof: Vec<String>,
) -> StdResult<Response> {
    let config = config_r(deps.storage).load()?;

    // Check that airdrop hasn't ended
    available(&config, env)?;

    // Get account
    let sender = info.sender.clone();
    let account = account_r(deps.storage).load(sender.to_string().as_bytes())?;

    // validate eth_signature
    validation::validate_claim(
        &deps,
        info.clone(),
        account.eth_pubkey.clone(), // uses the saved account eth_pubkey
        eth_sig,
        config.clone(),
    )?;

    // generate merkleTree leaf with eth_pubkey & amount
    let user_input = format!("{}{}", account.eth_pubkey, amount);
    let hash = sha2::Sha256::digest(user_input.as_bytes())
        .as_slice()
        .try_into()
        .map_err(|_| nothing_to_claim())?;

    let hash: [u8; 32] = proof.into_iter().try_fold(hash, |hash, p| {
        let mut proof_buf = [0; 32];
        hex::decode_to_slice(p, &mut proof_buf).unwrap();
        let mut hashes = [hash, proof_buf];
        hashes.sort_unstable();
        sha2::Sha256::digest(&hashes.concat())
            .as_slice()
            .try_into()
            .map_err(|_| wrong_length())
    })?;

    let merkle = config.merkle_root.clone();
    let mut root_buf: [u8; 32] = [0; 32];
    decode_to_slice(merkle, &mut root_buf).unwrap();
    ensure_eq!(root_buf, hash, failed_verification());

    if account.claimed == true {
        return Err(nothing_to_claim());
    }

    let redeem_amount = claim_tokens(deps.storage, env, info, &config, &account, amount)?;

    total_claimed_w(deps.storage)
        .update(|claimed| -> StdResult<Uint128> { Ok(claimed + redeem_amount) })?;

    Ok(Response::new()
        .set_data(to_binary(&ExecuteAnswer::Claim {
            status: ResponseStatus::Success,
            claimed: eth_pubkey_claim_r(deps.storage).load(eth_pubkey.as_bytes())?,
            addresses: account.addresses,
            eth_pubkey: account.eth_pubkey,
        })?)
        .add_message(send_msg(
            sender.clone(),
            redeem_amount.into(),
            None,
            None,
            None,
            &config.airdrop_snip20,
        )?))
}

pub fn try_claim_decay(deps: DepsMut, env: &Env, _info: &MessageInfo) -> StdResult<Response> {
    let config = config_r(deps.storage).load()?;

    // Check if airdrop ended
    if let Some(end_date) = config.end_date {
        if let Some(dump_address) = config.dump_address {
            if env.block.time.seconds() > end_date {
                decay_claimed_w(deps.storage).update(|claimed| {
                    if claimed {
                        Err(decay_claimed())
                    } else {
                        Ok(true)
                    }
                })?;

                let total_claimed = total_claimed_r(deps.storage).load()?;
                let send_total = config.airdrop_amount.checked_sub(total_claimed)?;
                let messages = vec![send_msg(
                    dump_address.clone(),
                    send_total.into(),
                    None,
                    None,
                    None,
                    &config.airdrop_snip20,
                )?];

                return Ok(Response::new()
                    .set_data(to_binary(&ExecuteAnswer::ClaimDecay { status: Success })?));
            }
        }
    }

    Err(decay_not_set())
}

pub fn claim_tokens(
    storage: &mut dyn Storage,
    env: &Env,
    info: &MessageInfo,
    config: &Config,
    account: &Account,
    amount: Uint128,
) -> StdResult<Uint128> {
    // send_amount
    let sender = account.eth_pubkey.to_string();

    // Amount to be redeemed

    // Update total claimed and calculate claimable
    eth_pubkey_claim_w(storage).update(sender.as_bytes(), |claimed| {
        if let Some(_claimed) = claimed {
            Err(already_claimed())
        } else {
            Ok(true)
        }
    })?;

    Ok(amount)
}

/// Validates all of the information and updates relevant states
pub fn try_add_account_addresses(
    storage: &mut dyn Storage,
    api: &dyn Api,
    config: &Config,
    sender: &Addr,
    account: &mut Account,
    addresses: Vec<AddressProofPermit>,
    eth_pubkey: String,
) -> StdResult<()> {
    // Setup the items to validate
    let mut leaves_to_validate: Vec<(usize, [u8; 32])> = vec![];

    // Iterate addresses
    for permit in addresses.iter() {
        if let Some(memo) = permit.memo.clone() {
            let params: AddressProofMsg = from_binary(&Binary::from_base64(&memo)?)?;

            // Avoid verifying sender
            if &params.address != sender {
                // Check permit legitimacy
                validate_address_permit(storage, api, permit, &params, config.contract.clone())?;
            }

            // Check that airdrop amount does not exceed maximum
            if params.amount > config.max_amount {
                return Err(claim_too_high(
                    params.amount.to_string().as_str(),
                    config.max_amount.to_string().as_str(),
                ));
            }

            // Update address if its not in an account
            address_in_account_w(storage).update(
                params.address.to_string().as_bytes(),
                |state| -> StdResult<bool> {
                    if state.is_some() {
                        return Err(address_already_in_account(params.address.as_str()));
                    }

                    Ok(true)
                },
            )?;

            // If valid then add to account array and sum total amount
            account.addresses.push(params.address);
        } else {
            return Err(expected_memo());
        }
    }
    Ok(())
}

pub fn available(config: &Config, env: &Env) -> StdResult<()> {
    let current_time = env.block.time.seconds();

    // Check if airdrop started
    if current_time < config.start_date {
        return Err(airdrop_not_started(
            config.start_date.to_string().as_str(),
            current_time.to_string().as_str(),
        ));
    }
    if let Some(end_date) = config.end_date {
        if current_time > end_date {
            return Err(airdrop_ended(
                end_date.to_string().as_str(),
                current_time.to_string().as_str(),
            ));
        }
    }

    Ok(())
}

/// Get the multiplier for decay, will return 1 when decay isnt in effect.
pub fn decay_factor(current_time: u64, config: &Config) -> Decimal {
    // Calculate redeem amount after applying decay
    if let Some(decay_start) = config.decay_start {
        if current_time >= decay_start {
            return inverse_normalizer(decay_start, current_time, config.end_date.unwrap());
        }
    }
    Decimal::one()
}

/// Get the inverse normalized value [0,1] of x between [min, max]
pub fn inverse_normalizer(min: u64, x: u64, max: u64) -> Decimal {
    Decimal::from_ratio(max - x, max - min)
}

// src: https://github.com/public-awesome/launchpad/blob/main/contracts/sg-eth-airdrop/src/claim_airdrop.rs#L85
pub mod validation {
    use super::*;
    use ethereum_verify::verify_ethereum_text;
    use shade_protocol::{airdrop::InstantiateMsg, c_std::StdError};

    pub fn validate_instantiation_params(
        info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<(), StdError> {
        // validate_airdrop_amount(msg.airdrop_amount)?;
        validate_plaintext_msg(msg.claim_msg_plaintext)?;
        // validate_instantiate_funds(info)?;
        Ok(())
    }

    pub fn compute_plaintext_msg(config: &Config, info: MessageInfo) -> String {
        str::replace(
            &config.claim_msg_plaintext,
            "{wallet}",
            info.sender.as_ref(),
        )
    }

    pub fn validate_claim(
        deps: &DepsMut,
        info: MessageInfo,
        eth_pubkey: String,
        eth_sig: String,
        config: Config,
    ) -> Result<(), StdError> {
        validate_eth_sig(deps, info, eth_pubkey.clone(), eth_sig, config)?;
        Ok(())
    }

    fn validate_eth_sig(
        deps: &DepsMut,
        info: MessageInfo,
        eth_pubkey: String,
        eth_sig: String,
        config: Config,
    ) -> Result<(), StdError> {
        let valid_eth_sig =
            validate_ethereum_text(deps, info, &config, eth_sig, eth_pubkey.clone())?;
        match valid_eth_sig {
            true => Ok(()),
            false => Err(StdError::generic_err("cannot validate eth_sig")),
        }
    }

    pub fn validate_ethereum_text(
        deps: &DepsMut,
        info: MessageInfo,
        config: &Config,
        eth_sig: String,
        eth_pubkey: String,
    ) -> StdResult<bool> {
        let plaintext_msg = compute_plaintext_msg(config, info);
        match hex::decode(eth_sig.clone()) {
            Ok(eth_sig_hex) => {
                verify_ethereum_text(deps.as_ref(), &plaintext_msg, &eth_sig_hex, &eth_pubkey)
            }
            Err(_) => Err(StdError::InvalidHex {
                msg: format!("Could not decode {eth_sig}"),
            }),
        }
    }

    pub fn validate_plaintext_msg(plaintext_msg: String) -> Result<(), StdError> {
        if !plaintext_msg.contains("{wallet}") {
            return Err(StdError::generic_err(
                "Plaintext message must contain `{{wallet}}` string",
            ));
        }
        if plaintext_msg.len() > 1000 {
            return Err(StdError::generic_err("Plaintext message is too long"));
        }
        Ok(())
    }
}
