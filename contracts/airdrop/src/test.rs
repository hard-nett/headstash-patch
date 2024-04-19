#[cfg(test)]
pub mod tests {
    use crate::handle::inverse_normalizer;
    use ethereum_verify::verify_ethereum_text;
    use sha2::Digest;
    use shade_protocol::{
        airdrop::{account::AddressProofMsg, errors::wrong_length},
        c_std::{
            from_binary, testing::mock_dependencies, Addr, Binary, Response, StdResult, Uint128,
        },
    };

    const ETH_PUBKEY: &str = "0x254768D47Cf8958a68242ce5AA1aDB401E1feF2B";
    const SLICED_ETH_SIG: &str = "f7992bd3f7cb1030b5d69d3326c6e2e28bfde2e38cbb8de753d1be7b5a5ecbcf2d3eccd3fe2e1fccb2454c47dcb926bd047ecf5b74c7330584cbfd619248de811b";
    const PLAINTEXT_MSG: &str = "secret13uazul89dp0lypuxcz0upygpjy0ftdah4lnrs4";

    #[test]
    fn test_valid_eth_sig() {
        let deps = mock_dependencies();
        let decoded = hex::decode(SLICED_ETH_SIG).unwrap();
        let res =
            verify_ethereum_text(deps.as_ref(), &PLAINTEXT_MSG, &decoded, &ETH_PUBKEY).unwrap();
        assert_eq!(true, res);
    }

    #[test]
    fn decay_factor() {
        assert_eq!(
            Uint128::new(50u128),
            Uint128::new(100u128) * inverse_normalizer(100, 200, 300)
        );

        assert_eq!(
            Uint128::new(25u128),
            Uint128::new(100u128) * inverse_normalizer(0, 75, 100)
        );
    }

    const MSGTYPE: &str = "wasm/MsgExecuteContract";

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
}
