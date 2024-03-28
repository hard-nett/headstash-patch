# Private Headstash Airdrop

### InstantiateMsg
## Init
##### Request
| Name           | Type          | Description                                                                | optional |
|----------------|---------------|----------------------------------------------------------------------------|----------|
| admin          | String        | New contract owner; SHOULD be a valid bech32 address                       | yes      |
| dump_address   | String        | Where the decay amount will be sent                                        | yes      |
| airdrop_token  | Contract      | The token that will be airdropped                                          | no       |
| airdrop_2      | Contract      | The 2nd token that will be airdropped                                      | yes      |
| airdrop_amount | String        | Total airdrop amount to be claimed                                         | no       |
| start_date     | u64           | When the airdrop starts in UNIX time                                       | yes      |
| end_date       | u64           | When the airdrop ends in UNIX time                                         | yes      |
| decay_start    | u64           | When the airdrop decay starts in UNIX time                                 | yes      |
| merkle_root    | String        | Base 64 encoded merkle root of the airdrop data tree                       | no       |
| total_accounts | u32           | Total accounts in airdrop (needed for merkle proof)                        | no       |
| max_amount     | String        | Used to limit the user permit amounts (lowers exploit possibility)         | no       |
| default_claim  | String        | The default amount to be gifted regardless of tasks                        | no       |
| claim_msg_plaintext     | String | {wallet}                                                                 | no       |
| query_rounding | string        | To prevent leaking information, total claimed is rounded off to this value | no       |

### ExecuteMsg

### Account
(Creates / Updates) an account from which the user will claim all of his given addresses' rewards
##### Request
| Name         | Type                                               | Description                                               | optional |
|--------------|----------------------------------------------------|-----------------------------------------------------------|----------|
| addresses    | Array of [AddressProofPermit](#AddressProofPermit) | Proof that the user owns those addresses                  | no       |
| eth_pubkey   | string                                             | Key included in headstash distribution     | no       |
| padding      | string                                             | Allows for enforcing constant length messages             | yes      |

##### Response
```json
{}
```

### SetViewingKey
Sets a viewing key for the account, useful for when the network is congested because of permits.
##### Request
| Name    | Type   | Description                                   | optional |
|---------|--------|-----------------------------------------------|----------|
| key     | string | Viewing key                                   | no       |
| padding | string | Allows for enforcing constant length messages | yes      |

##### Response
```json
{
  "set_viewing_key": {
    "status": "success"
  }
}
```

### DisablePermitKey
Disables that permit's key. Any permit that has that key for that address will be declined.
##### Request
| Name    | Type   | Description                                   | optional |
|---------|--------|-----------------------------------------------|----------|
| key     | string | Permit key                                    | no       |
| padding | string | Allows for enforcing constant length messages | yes      |

##### Response
```json
{
  "disable_permit_key": {
    "status": "success"
  }
}
```

### QueryMsg