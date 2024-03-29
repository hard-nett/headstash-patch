
pub mod oracles;

#[cfg(feature = "snip20")]
pub mod snip20;

// Protocol init libraries
#[cfg(feature = "airdrop")]
pub mod airdrop;

#[cfg(feature = "query_auth")]
pub mod query_auth;

#[cfg(feature = "admin")]
pub mod admin;
