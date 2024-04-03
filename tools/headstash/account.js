import { MsgExecuteContract, toUtf8 } from "secretjs";
import { encodeJsonToB64 } from "@shadeprotocol/shadejs";
import { scrtHeadstashCodeHash, secretHeadstashContractAddr, secretjs, txEncryptionSeed, wallet } from "./main.js";

const viewingKey = "eretskeretjableret"
const eth_pubkey = "0x254768D47Cf8958a68242ce5AA1aDB401E1feF2B";
const eth_sig = "0xf7992bd3f7cb1030b5d69d3326c6e2e28bfde2e38cbb8de753d1be7b5a5ecbcf2d3eccd3fe2e1fccb2454c47dcb926bd047ecf5b74c7330584cbfd619248de811b" 

// filler message of AddressProofPermit
const fillerMsg = {
  contract: secretHeadstashContractAddr,
  execute_msg: {},
  sender: wallet.address,
}

// data to be encoded in memo of AddressProofPermit
const addrProofMsg = {
  address: wallet.address,
  contract: secretHeadstashContractAddr,
  key: 'eretskeretjableret'
}
// Convert JSON object to JSON string
let jsonString = JSON.stringify(addrProofMsg, (key, value) => {
  if (typeof value === 'string') {
      return value.replace(/\\/g, '');
  }
  return value;
});
const encoded = encodeJsonToB64(jsonString);



console.log("AddrProofMsg:", jsonString);
console.log("Base64 String of AddrProofMsg:", encoded)

// signature documentate as defined here: 
// https://github.com/securesecrets/shade/blob/77abdc70bc645d97aee7de5eb9a2347d22da425f/packages/shade_protocol/src/signature/mod.rs#L100

const createAccount = new MsgExecuteContract({
  sender: wallet.address,
  contract_address: secretHeadstashContractAddr,
  code_hash: scrtHeadstashCodeHash,
  msg: {
    account: {
      addresses: [
        {
          params: fillerMsg,
          signature: {
            pub_key: {
              type: "tendermint/PubKeySecp256k1",
              value: "AyZtxhLgis4Ec66OVlKDnuzEZqqV641sm46R3mbE2cpO",
            },
            signature: "tTjK3Mf4dpQrSQT2hsqXn+pgeXhVjQhw2EXP5N50uhBJ0kpV9IS5uyfo+PHvB20CVHMwux9leaByfXI3T6PD6A==",
          },
          account_number: null,
          chain_id: null,
          sequence: null,
          memo: encoded,
        }
      ],
      eth_pubkey: eth_pubkey,
      eth_sig: eth_sig.slice(2),
    }
  },
  sent_funds: [], // optional
});

const tx = await secretjs.tx.broadcast([createAccount], {
  gasLimit: 200_000,
});

console.log(tx);



