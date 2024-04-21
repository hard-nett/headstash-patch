use std::convert::TryInto;

use crate::{
    query,
    state::{claim_status_r, claim_status_w, config_r, config_w, total_claimed_w},
};
use sha2::Digest;
use shade_protocol::{
    airdrop::{Config, ExecuteMsg, InstantiateMsg, QueryAnswer, QueryMsg},
    c_std::{
        shd_entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError,
        StdResult, Uint128,
    },
    snip20::helpers::send_msg,
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
    let config = Config {
        snip20_1: msg.snip20_1,
        snip20_2: msg.snip20_2,
        merkle_root: msg.merkle_root,
        viewing_key: msg.viewing_key,
        admin: Some(msg.admin.unwrap_or(info.sender)),
        claim_msg_plaintext: msg.claim_msg_plaintext,
    };

    config_w(deps.storage).save(&config)?;

    // Initialize claim amount
    total_claimed_w(deps.storage).save(&Uint128::zero())?;

    Ok(Response::new())
}

#[shd_entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    pad_handle_result(
        match msg {
            ExecuteMsg::Claim {
                amount,
                eth_pubkey,
                eth_sig,
                proof,
            } => try_claim(deps, env, info, amount, eth_pubkey, eth_sig, proof),
            ExecuteMsg::Clawback {} => todo!(),
        },
        RESPONSE_BLOCK_SIZE,
    )
}

pub fn try_claim(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    amount: Uint128,
    eth_pubkey: String,
    eth_sig: String,
    proofs: Vec<String>,
) -> StdResult<Response> {
    let config = config_r(deps.storage).load()?;

    // make sure airdrop has not ended

    // validate eth_signature comes from eth pubkey.
    // Occurs before claim check to prevent data leak of eth_pubkey claim status.
    validation::validate_claim(
        &deps,
        info.clone(),
        eth_pubkey.clone(),
        eth_sig.clone(),
        config.clone(),
    )?;

    // check if address has already claimed
    let state = claim_status_r(deps.storage).may_load(eth_pubkey.as_bytes())?;
    if state == Some(true) {
        return Err(StdError::generic_err(
            "You have already claimed your headstash, homie!",
        ));
    }

    // validate merkle leafs to proofs
    let user_input = format!("{}{}", eth_pubkey, amount);
    let hash = sha2::Sha256::digest(user_input.as_bytes())
        .as_slice()
        .try_into()
        .map_err(|_| StdError::generic_err("Wrong length - debug69)"))?;

    let hash = proofs.into_iter().try_fold(hash, |hash, p| {
        let mut proof_buf = [0; 32];
        hex::decode_to_slice(p, &mut proof_buf)
            .expect("merkle verification process error - debug710");
        let mut hashes = [hash, proof_buf];
        hashes.sort_unstable();
        sha2::Sha256::digest(&hashes.concat())
            .as_slice()
            .try_into()
            .map_err(|_| StdError::generic_err("Wrong length - debug420"))
    })?;

    let mut root_buf: [u8; 32] = [0; 32];
    hex::decode_to_slice(config.merkle_root.as_ref(), &mut root_buf)
        .expect("merkle verification process error - debug711");
    if root_buf != hash {
        return Err(StdError::generic_err("Failed to verify merkle proofs!"));
    }

    let mut msgs = vec![];

    msgs.push(send_msg(
        info.sender,
        amount,
        None,
        None,
        None,
        &config.snip20_1,
    )?);

    // update address as claimed
    claim_status_w(deps.storage).save(eth_pubkey.as_bytes(), &true)?;
    // update total_claimed
    total_claimed_w(deps.storage)
        .update(|claimed| -> StdResult<Uint128> { Ok(claimed + amount) })?;

    Ok(
        Response::default(), // .add_messages(msgs)
    )
}

#[shd_entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    pad_query_result(
        match msg {
            QueryMsg::Config {} => to_binary(&query_config(deps)?),
        },
        RESPONSE_BLOCK_SIZE,
    )
}

fn query_config(deps: Deps) -> StdResult<QueryAnswer> {
    let state = config_r(deps.storage).load()?;
    Ok(QueryAnswer::HeadstashConfigResponse {
        config: config_r(deps.storage).load()?,
    })
}

// src: https://github.com/public-awesome/launchpad/blob/main/contracts/sg-eth-airdrop/src/claim_airdrop.rs#L85
pub mod validation {

    use crate::verify::verify_ethereum_text;

    use super::*;

    pub fn validate_instantiation_params(
        _info: MessageInfo,
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
