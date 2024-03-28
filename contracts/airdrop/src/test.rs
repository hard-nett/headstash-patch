#[cfg(test)]
pub mod tests {
    use crate::contract::{execute, query};
    use crate::{contract::instantiate, handle::inverse_normalizer};
    use shade_protocol::query_authentication::permit::Permit;
    use shade_protocol::{
        airdrop::{ExecuteMsg, QueryMsg},
        c_std::testing::mock_dependencies_with_balance,
    };

    use shade_protocol::{
        airdrop::{
            account::{AddressProofMsg, AddressProofPermit, FillerMsg},
            InstantiateMsg,
        },
        c_std::{
            from_binary,
            testing::{mock_dependencies, mock_env, mock_info},
            Addr, Binary, Coin, Uint128,
        },
        query_authentication::{
            permit::bech32_to_canonical,
            transaction::{PermitSignature, PubKey},
        },
        Contract,
    };

    const VIEWING_KEY: &str = "jUsTfOrTeStInG";

    fn proper_initialization() {
        let mut deps = mock_dependencies();
        let info = mock_info(
            "creator",
            &[Coin {
                denom: "earth".to_string(),
                amount: Uint128::new(1000),
            }],
        );

        let init_msg = InstantiateMsg {
            admin: Some(Addr::unchecked("creator")),
            dump_address: Some(Addr::unchecked("creator")),
            airdrop_token: Contract::new(
                &Addr::unchecked("secret-terps"),
                &"xyx-code-hash".to_string(),
            ),
            airdrop_2: Contract::new(
                &Addr::unchecked("secret-thiol"),
                &"xyz-code-hash".to_string(),
            ),
            airdrop_amount: Uint128::new(420),
            start_date: None,
            end_date: None,
            decay_start: None,
            merkle_root: "77fb25152b72ac67f5a155461e396b0788dd0567ec32a96f8201b899ad516b02"
                .to_string(),
            total_accounts: 12580u32,
            claim_msg_plaintext: "{wallet}".to_string(),
        };

        let res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

        assert_eq!(0, res.messages.len());
    }

    mod account {
        use shade_protocol::{airdrop::account::EmptyMsg, c_std::to_binary};

        use super::*;

        #[test]
        fn set_viewing_key() {
            let mut deps = mock_dependencies_with_balance(&[Coin {
                denom: "earth".to_string(),
                amount: Uint128::new(1000),
            }]);
            let info = mock_info(
                "creator",
                &[Coin {
                    denom: "earth".to_string(),
                    amount: Uint128::new(1000),
                }],
            );

            let init_msg = InstantiateMsg {
                admin: Some(Addr::unchecked("creator")),
                dump_address: Some(Addr::unchecked("creator")),
                airdrop_token: Contract::new(
                    &Addr::unchecked("secret-terps"),
                    &"xyx-code-hash".to_string(),
                ),
                airdrop_2: Contract::new(
                    &Addr::unchecked("secret-thiol"),
                    &"xyz-code-hash".to_string(),
                ),
                airdrop_amount: Uint128::new(420),
                start_date: None,
                end_date: None,
                decay_start: None,
                merkle_root: "77fb25152b72ac67f5a155461e396b0788dd0567ec32a96f8201b899ad516b02"
                    .to_string(),
                total_accounts: 12580u32,
                claim_msg_plaintext: "{wallet}".to_string(),
            };

            let _res = instantiate(deps.as_mut(), mock_env(), info, init_msg).unwrap();

            // anyone can setup an account
            let info = mock_info(
                "anyone",
                &[Coin {
                    denom: "token".to_string(),
                    amount: Uint128::new(420),
                }],
            );
            // test setting a viewing key
            let exec_msg = ExecuteMsg::SetViewingKey {
                key: VIEWING_KEY.into(),
                padding: None,
            };
            let res = execute(deps.as_mut(), mock_env(), info.clone(), exec_msg).unwrap();
            println!("{res:?}");

            // test disabling the permit key
            let exec_msg = ExecuteMsg::DisablePermitKey {
                key: VIEWING_KEY.into(),
                padding: None,
            };
            let res = execute(deps.as_mut(), mock_env(), info, exec_msg).unwrap();
            assert_eq!(0, res.messages.len());
        }

        #[test]
        fn claim_headstash() {}
        #[test]
        fn create_account() {}
    }
    #[test]
    fn test_s_i_e_q() {
        let deps = mock_dependencies();
    }

    #[test]
    fn memo_deserialization() {
        let expected_memo = AddressProofMsg {
            address: Addr::unchecked("secret19q7h2zy8mgesy3r39el5fcm986nxqjd7cgylrz".to_string()),
            amount: Uint128::new(1000000u128),
            contract: Addr::unchecked("secret1sr62lehajgwhdzpmnl65u35rugjrgznh2572mv".to_string()),
            index: 10,
            key: "account-creation-permit".to_string(),
        };

        let deserialized_memo: AddressProofMsg = from_binary(
            &Binary::from_base64(
                &"eyJhZGRyZXNzIjoic2VjcmV0MTlxN2gyenk4bWdlc3kzcjM5ZWw1ZmNtOTg2bnhxamQ3Y2d5bHJ6IiwiYW1vdW50IjoiMTAwMDAwMCIsImNvbnRyYWN0Ijoic2VjcmV0MXNyNjJsZWhhamd3aGR6cG1ubDY1dTM1cnVnanJnem5oMjU3Mm12IiwiaW5kZXgiOjEwLCJrZXkiOiJhY2NvdW50LWNyZWF0aW9uLXBlcm1pdCJ9"
                    .to_string()).unwrap()).unwrap();

        assert_eq!(deserialized_memo, expected_memo)
    }

    #[test]
    fn claim_query() {}

    #[test]
    fn claim_query_odd_multiple() {}

    #[test]
    fn claim_query_under_step() {}
}
