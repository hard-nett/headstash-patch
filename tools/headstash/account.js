import { MsgExecuteContract, fromBase64, toUtf8 } from "secretjs";
import { encodeJsonToB64 } from "@shadeprotocol/shadejs";
import { chain_id, scrtHeadstashCodeHash, secretHeadstashContractAddr, secretjs, txEncryptionSeed, wallet } from "./main.js";

const cosmos_sig = "c5uzRIuxO91I8BYxJ8CREuHoDkhH4wJXa5W8mng/gbhXnhAQQ9WEYsGkJHtEK8Ppnt6rXG/IcvL7x7AdBbmpfw==";
const eth_pubkey = "0x254768D47Cf8958a68242ce5AA1aDB401E1feF2B";
const eth_sig = "0xf7992bd3f7cb1030b5d69d3326c6e2e28bfde2e38cbb8de753d1be7b5a5ecbcf2d3eccd3fe2e1fccb2454c47dcb926bd047ecf5b74c7330584cbfd619248de811b"
const pubkey = { type: "tendermint/PubKeySecp256k1", value: "AyZtxhLgis4Ec66OVlKDnuzEZqqV641sm46R3mbE2cpO" }
const partial_tree = ['fbff7c66d3f610bcf8223e61ce12b10bb64a3433622ff39af83443bcec78920a']
const permitKey = ""


const addressProofMsg = {
  address: wallet.address,
  amount: "",
  contract: secretHeadstashContractAddr,
  index: 1,
  key: permitKey,
}

// Convert memo to single string
let addrProofMsgJson = JSON.stringify(addressProofMsg, (key, value) => {
  if (typeof value === 'string') {
    return value.replace(/\\/g, '');
  }
  return value;
});

// encode memo to base64 string
const encoded_memo = encodeJsonToB64(addrProofMsgJson);

const fillerMsg = {
  coins: [],
  contract: secretHeadstashContractAddr,
  execute_msg: "",
  sender: wallet.address,
}

// account
const permitParams = {
  params: fillerMsg,
  memo: encoded_memo,
  chain_id: chain_id,
  signature: {
    pub_key: pubkey,
    signature: cosmos_sig,
  },
}

console.log("PubKey:", pubkey);
console.log("AddrProofMsg:", addrProofMsgJson);
console.log("Encoded AddrProofMsg:", encoded_memo);
// console.log("Encoded Partial Key:", encoded_partial_tree);

// signature documentate as defined here: 
// https://github.com/securesecrets/shade/blob/77abdc70bc645d97aee7de5eb9a2347d22da425f/packages/shade_protocol/src/signature/mod.rs#L100
const createAccount = new MsgExecuteContract({
  sender: wallet.address,
  contract_address: secretHeadstashContractAddr,
  code_hash: scrtHeadstashCodeHash,
  msg: {
    account: {
      addresses: [permitParams],
      eth_pubkey: eth_pubkey,
      eth_sig: eth_sig.slice(2),
      partial_tree: partial_tree,
    }
  },
  sent_funds: [], // optional
});

const tx = await secretjs.tx.broadcast([createAccount], {
  gasLimit: 200_000,
  // explicitSignerData: {
  //   accountNumber: 22761,
  //   sequence: 170,
  //   chainId: "pulsar-3"
  // }
});

console.log(tx);



