import { MsgExecuteContract, fromBase64, toUtf8 } from "secretjs";
import { encodeJsonToB64 } from "@shadeprotocol/shadejs";
import { chain_id, scrtHeadstashCodeHash, secretHeadstashContractAddr, secretjs, txEncryptionSeed, wallet } from "./main.js";

const viewingKey = "eretskeretjableret"
const eth_pubkey = "0x254768D47Cf8958a68242ce5AA1aDB401E1feF2B";
const eth_sig = "0xf7992bd3f7cb1030b5d69d3326c6e2e28bfde2e38cbb8de753d1be7b5a5ecbcf2d3eccd3fe2e1fccb2454c47dcb926bd047ecf5b74c7330584cbfd619248de811b"
const cosmos_sig = "0x";
const pubkey = {
  type: "tendermint/PubKeySecp256k1",
  value: "AyZtxhLgis4Ec66OVlKDnuzEZqqV641sm46R3mbE2cpO",
}
const partial_tree = ['fbff7c66d3f610bcf8223e61ce12b10bb64a3433622ff39af83443bcec78920a']

// filler message of AddressProofPermit
const fillerMsg = {
  coins: [
    { denom: "uterpx", amount: "420" },
    { denom: "uthiolx", amount: "420" }
  ],
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

// Convert memo to single string
let addrProofMsgJson = JSON.stringify(addrProofMsg, (key, value) => {
  if (typeof value === 'string') {
    return value.replace(/\\/g, '');
  }
  return value;
});

// Convert memo to single string
let partialTreeJson = JSON.stringify(partial_tree, (key, value) => {
  if (typeof value === 'string') {
    return value.replace(/\\/g, '');
  }
  return value;
});

// encode memo to base64 string
const encoded_memo = encodeJsonToB64(addrProofMsgJson);
const encoded_partial_tree = encodeJsonToB64(partialTreeJson);

console.log("PubKey:", pubkey);
console.log("AddrProofMsg:", addrProofMsgJson);
console.log("Encoded AddrProofMsg:", encoded_memo);
console.log("Encoded Partial Key:", encoded_partial_tree);

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
          chain_id: chain_id,
          sequence: null,
          signature: {
            pub_key: pubkey,
            signature: cosmos_sig,
          },
          memo: encoded_memo,
        }
      ],
      eth_pubkey: eth_pubkey,
      eth_sig: eth_sig.slice(2),
      partial_tree: encoded_partial_tree,
    }
  },
  sent_funds: [], // optional
});

const tx = await secretjs.tx.broadcast([createAccount], {
  gasLimit: 200_000,
});

console.log(tx);



