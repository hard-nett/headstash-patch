use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr};
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub num_members: u32,
    pub claim_limit: u32,
}

#[cw_serde]
pub struct AdminList {
    pub admins: Vec<Addr>,
    pub mutable: bool,
}

impl AdminList {
    pub fn is_admin(&self, addr: impl AsRef<str>) -> bool {
        let addr = addr.as_ref();
        self.admins.iter().any(|a| a.as_ref() == addr)
    }

    pub fn can_modify(&self, addr: &str) -> bool {
        self.mutable && self.is_admin(addr)
    }
}

pub const ADMIN_LIST: Item<AdminList> = Item::new("admin_list");

pub const CONFIG: Item<Config> = Item::new("config");

// address <> claim_count
pub const GOOPLIST: Map<String, u32> = Map::new("gl");
// address <> amount
pub const HEADSTASH_AMOUNT: Map<String, u32> = Map::new("ha");

