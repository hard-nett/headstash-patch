#[cfg(feature = "admin")]
pub mod admin {
    pub use admin;
    use shade_protocol::{admin::InstantiateMsg, multi_test::App, utils::InstantiateCallback};
    multi_derive::implement_multi!(Admin, admin);

    // Multitest helper
    pub fn init_admin_auth(app: &mut App, superadmin: &Addr) -> ContractInfo {
        InstantiateMsg {
            super_admin: Some(superadmin.clone().to_string()),
        }
        .test_init(Admin::default(), app, superadmin.clone(), "admin_auth", &[])
        .unwrap()
    }
}

#[cfg(feature = "snip20")]
pub mod snip20 {
    use snip20;
    multi_derive::implement_multi!(Snip20, snip20);
}