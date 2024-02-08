use crate::state::{
    account_r,
    // account_total_claimed_r,
    // account_total_claimed_w,
    account_viewkey_w,
    account_w,
    address_in_account_w,
    claim_status_w,
    config_r,
    config_w,
    decay_claimed_w,
    eth_pubkey_claim_r,
    eth_pubkey_claim_w,
    eth_pubkey_in_account_w,
    revoke_permit,
    total_claimed_r,
    total_claimed_w,
    validate_address_permit,
};
use hex::decode_to_slice;
use rs_merkle::{algorithms::Sha256, Hasher};
use sha2::Digest;
use shade_protocol::{
    airdrop::{
        account::{Account, AccountKey, AddressProofMsg, AddressProofPermit},
        errors::{
            address_already_in_account, airdrop_ended, airdrop_not_started, already_claimed,
            decay_claimed, decay_not_set, expected_memo, failed_verification, invalid_dates,
            not_admin, nothing_to_claim, wrong_length,
        },
        Config, ExecuteAnswer,
    },
    c_std::{
        ensure_eq, from_binary, to_binary, Addr, Api, Binary, Decimal, DepsMut, Env, MessageInfo,
        Response, StdResult, Storage, Uint128,
    },
    snip20::helpers::send_msg,
    utils::generic_response::ResponseStatus::{self},
};
use shade_protocol::{
    contract_interfaces::query_auth::{
        auth::{HashedKey, Key, PermitKey},
        RngSeed,
    },
    query_authentication::viewing_keys::ViewingKey,
    utils::{
        generic_response::ResponseStatus::Success,
        storage::plus::{ItemStorage, MapStorage},
    },
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
) -> StdResult<Response> {
    let config = config_r(deps.storage).load()?;
    // Check if admin
    assert!(
        info.sender == config.admin,
        not_admin(config.admin.as_str())
    );

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

            state.start_date = start_date;
        }
        if let Some(end_date) = end_date {
            // Avoid date collisions
            state.end_date = Some(end_date);
        }

        Ok(state)
    })?;
    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::UpdateConfig { status: Success })?))
}

pub fn try_account(
    deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    eth_pubkey: String,
    addresses: Vec<AddressProofPermit>,
) -> StdResult<Response> {
    // 1. Check if airdrop active
    // 2. Check that airdrop hasn't ended
    // 3. Setup account by cosmos signer
    // 4. These variables are setup to facilitate updating
    let config = config_r(deps.storage).load()?;
    available(&config, env)?;
    let sender = info.sender.to_string();
    let updating_account: bool;

    // define the msg senders account
    let mut account: Account = match account_r(deps.storage).may_load(sender.clone().as_bytes())? {
        None => {
            updating_account = false;
            // setup a new account with addresses & eth_pubkey
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
            claim_status_w(deps.storage, 0).save(account.eth_pubkey.as_bytes(), &false)?;

            account
        }
        Some(acc) => {
            updating_account = true;
            acc
        }
    };

    // Update account after claim to calculate difference,
    // and to save eth_pubkey as saved to the contract state.
    if updating_account {
        // Validate permits
        try_add_account_addresses(
            deps.storage,
            deps.api,
            &config,
            &info.sender,
            &mut account,
            addresses.clone(),
            eth_pubkey,
        )?;
    }

    // Save account
    account_w(deps.storage).save(sender.as_bytes(), &account)?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::Account {
        status: ResponseStatus::Success,
        claimed: eth_pubkey_claim_r(deps.storage)
            .load(account.eth_pubkey.to_string().as_bytes())?,
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

// claim an airdrop, privately. Must have created an account & signing keys prior
pub fn try_claim(
    deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    amount: Uint128,
    eth_pubkey: String,
    eth_sig: String,
    proof: Vec<String>,
) -> StdResult<Response> {
    let config: Config = config_r(deps.storage).load()?;

    // Check that airdrop hasn't ended
    available(&config, env)?;

    // Get account from the msg sender, restricting access to query account
    // via eth_pubkey, as well as verify eth_sig was generated with account.eth_pubkey
    let sender = info.sender.clone();
    let account = account_r(deps.storage).load(sender.clone().as_bytes())?;

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
    // Claim airdrop
    let mut messages = vec![];
    let mut redeem_amount = Uint128::zero();
    // check if eth_pubkey has already claimed
    if account.claimed == false {
        redeem_amount = claim_tokens(deps.storage, &eth_pubkey, &amount)?;
    } else {
        return Err(nothing_to_claim());
    }

    // update global claimed amount
    total_claimed_w(deps.storage)
        .update(|claimed| -> StdResult<Uint128> { Ok(claimed + redeem_amount) })?;

    messages.push(send_msg(
        info.sender.clone(),
        redeem_amount.into(),
        None,
        None,
        None,
        &config.airdrop_snip20,
    )?);

    claim_status_w(deps.storage, 0).save(account.eth_pubkey.as_bytes(), &true)?;

    Ok(Response::new()
        .set_data(to_binary(&ExecuteAnswer::Claim {
            status: ResponseStatus::Success,
            claimed: eth_pubkey_claim_r(deps.storage).load(eth_pubkey.as_bytes())?,
            addresses: account.addresses,
            eth_pubkey,
        })?)
        .add_message(send_msg(
            sender.clone(),
            redeem_amount.into(),
            None,
            None,
            None,
            &config.airdrop_snip20,
        )?)
        .add_message(send_msg(
            sender.clone(),
            redeem_amount.into(),
            None,
            None,
            None,
            &config.airdrop_snip20_optional,
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
                let messages = vec![
                    {
                        send_msg(
                            dump_address.clone(),
                            send_total.into(),
                            None,
                            None,
                            None,
                            &config.airdrop_snip20,
                        )
                    },
                    {
                        send_msg(
                            dump_address.clone(),
                            send_total.into(),
                            None,
                            None,
                            None,
                            &config.airdrop_snip20_optional,
                        )
                    },
                ];

                return Ok(Response::new()
                    .set_data(to_binary(&ExecuteAnswer::ClaimDecay { status: Success })?));
            }
        }
    }

    Err(decay_not_set())
}

pub fn claim_tokens(
    storage: &mut dyn Storage,
    eth_pubkey: &String,
    amount: &Uint128,
) -> StdResult<Uint128> {
    // Save the eth_pubkey to state, if eth_pubkey already exist, error on claim
    eth_pubkey_claim_w(storage).update(eth_pubkey.as_bytes(), |claimed| {
        if let Some(_claimed) = claimed {
            Err(already_claimed())
        } else {
            Ok(true)
        }
    })?;
    Ok(*amount)
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
            // unwrap the permits, coming from the message memo
            let params: AddressProofMsg = from_binary(&Binary::from_base64(&memo)?)?;

            // Avoid verifying sender
            if &params.address != sender {
                // Check permit legitimacy
                validate_address_permit(storage, api, permit, &params, config.contract.clone())?;
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

            // Update eth_pubkey if its not in an account
            // remember, this is unverified and checked when a eth_sig
            // is provided, preventing unauthorized claim status queries
            //
            eth_pubkey_in_account_w(storage).update(
                eth_pubkey.to_string().as_bytes(),
                |state| -> StdResult<bool> {
                    if state.is_some() {
                        return Err(address_already_in_account(eth_pubkey.as_str()));
                    }
                    Ok(true)
                },
            )?;

            // Add account as a leaf
            let leaf_hash =
                Sha256::hash((params.address.to_string() + &params.amount.to_string()).as_bytes());
            leaves_to_validate.push((params.index as usize, leaf_hash));

            // If valid then add to account array and sum total amount
            account.addresses.push(params.address);
            account.eth_pubkey = eth_pubkey.clone();
        } else {
            return Err(expected_memo());
        }
    }

    // Need to sort by index in order for the proof to work
    leaves_to_validate.sort_by_key(|item| item.0);

    let mut indices: Vec<usize> = vec![];
    let mut leaves: Vec<[u8; 32]> = vec![];

    for leaf in leaves_to_validate.iter() {
        indices.push(leaf.0);
        leaves.push(leaf.1);
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

/// Get the inverse normalized value [0,1] of x between [min, max]
pub fn inverse_normalizer(min: u64, x: u64, max: u64) -> Decimal {
    Decimal::from_ratio(max - x, max - min)
}

// src: https://github.com/public-awesome/launchpad/blob/main/contracts/sg-eth-airdrop/src/claim_airdrop.rs#L85
mod validation {
    use super::*;
    use ethereum_verify::verify_ethereum_text;
    use shade_protocol::c_std::StdError;

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
}

// create viewing keys
pub fn try_create_viewing_key(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    entropy: String,
) -> StdResult<Response> {
    let seed = RngSeed::load(deps.storage)?.0;

    let key = Key::generate(&info, &env, seed.as_slice(), &entropy.as_ref());

    HashedKey(key.hash()).save(deps.storage, info.sender)?;

    Ok(Response::new().set_data(to_binary(&ExecuteAnswer::CreateViewingKey { key: key.0 })?))
}
