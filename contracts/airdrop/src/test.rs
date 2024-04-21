// #[cfg(test)]
// mod tests {
//     use crate::contract::{execute, instantiate, query};

//     use super::*;

//     use shade_protocol::{
//         airdrop::{ExecuteMsg, InstantiateMsg, QueryMsg},
//         c_std::{
//             testing::{mock_dependencies, mock_dependencies_with_balance, mock_env, mock_info},
//             Coin, StdError, Uint128,
//         },
//     };

//     #[test]
//     fn proper_initialization() {
//         let mut deps = mock_dependencies();
//         let info = mock_info(
//             "creator",
//             &[Coin {
//                 denom: "earth".to_string(),
//                 amount: Uint128::new(1000),
//             }],
//         );
//         let init_msg = InstantiateMsg {
//             snip20_1: todo!(),
//             snip20_2: todo!(),
//             merkle_root: todo!(),
//             viewing_key: todo!(),
//             total_amount: todo!(),
//             claim_msg_plaintext: todo!(),
//             admin: todo!(),
//         };

//         // we can just call .unwrap() to assert this was a success
//         let res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

//         assert_eq!(0, res.messages.len());

//         // it worked, let's query the state
//         let res = query(deps.as_ref(), mock_env(), QueryMsg::Config {}).unwrap();
//         // assert_eq!(17, value.count);
//     }

//     #[test]
//     fn increment() {
//         let mut deps = mock_dependencies_with_balance(&[Coin {
//             denom: "token".to_string(),
//             amount: Uint128::new(2),
//         }]);
//         let info = mock_info(
//             "creator",
//             &[Coin {
//                 denom: "token".to_string(),
//                 amount: Uint128::new(2),
//             }],
//         );
//         let init_msg = InstantiateMsg {
//             snip20_1: todo!(),
//             snip20_2: todo!(),
//             merkle_root: todo!(),
//             viewing_key: todo!(),
//             total_amount: todo!(),
//             claim_msg_plaintext: todo!(),
//             admin: todo!(),
//         };

//         let _res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

//         // anyone can increment
//         let info = mock_info(
//             "anyone",
//             &[Coin {
//                 denom: "token".to_string(),
//                 amount: Uint128::new(2),
//             }],
//         );

//         let exec_msg = ExecuteMsg::Claim {
//             amount: todo!(),
//             eth_pubkey: todo!(),
//             eth_sig: todo!(),
//             proof: todo!(),
//         };
//         let _res = execute(deps.as_mut(), mock_env(), info, exec_msg).unwrap();

//         // should increase total claimed by 420
//         let res = query(deps.as_ref(), mock_env(), QueryMsg::Config {}).unwrap();
//         // let value: CountResponse = from_binary(&res).unwrap();
//         // assert_eq!(420, value);
//     }

//     #[test]
//     fn reset() {
//         let mut deps = mock_dependencies_with_balance(&[Coin {
//             denom: "token".to_string(),
//             amount: Uint128::new(2),
//         }]);
//         let info = mock_info(
//             "creator",
//             &[Coin {
//                 denom: "token".to_string(),
//                 amount: Uint128::new(2),
//             }],
//         );
//         let init_msg = InstantiateMsg {
//             snip20_1: todo!(),
//             snip20_2: todo!(),
//             merkle_root: todo!(),
//             viewing_key: todo!(),
//             total_amount: todo!(),
//             claim_msg_plaintext: todo!(),
//             admin: todo!(),
//         };

//         let _res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

//         // not anyone can reset
//         let info = mock_info(
//             "anyone",
//             &[Coin {
//                 denom: "token".to_string(),
//                 amount: Uint128::new(2),
//             }],
//         );
//         let exec_msg = ExecuteMsg::Clawback {};

//         let res = execute(deps.as_mut(), mock_env(), info, exec_msg);

//         match res {
//             Err(StdError::GenericErr { .. }) => {}
//             _ => panic!("Must return unauthorized error"),
//         }

//         // only the original creator can clawback
//         let info = mock_info(
//             "creator",
//             &[Coin {
//                 denom: "token".to_string(),
//                 amount: Uint128::new(2),
//             }],
//         );
//         let exec_msg = ExecuteMsg::Clawback {};

//         let _res = execute(deps.as_mut(), mock_env(), info, exec_msg).unwrap();

//         // should now be clawedback
//         // let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
//         // // let value: CountResponse = from_binary(&res).unwrap();
//         // assert_eq!(5, value.count);
//     }
// }
