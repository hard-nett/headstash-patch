use shade_protocol::utils::asset::Contract;
use std::collections::HashMap;

#[derive(Clone, Eq, PartialEq, Hash)]
pub enum SupportedContracts {
    Snip20(String),
}

pub type DeployedContracts = HashMap<SupportedContracts, Contract>;
