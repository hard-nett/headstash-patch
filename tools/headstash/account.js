import { MsgExecuteContract, fromBase64, toUtf8 } from "secretjs";
import { encodeJsonToB64 } from "@shadeprotocol/shadejs";
import { chain_id, scrtHeadstashCodeHash, secretHeadstashContractAddr, secretjs, txEncryptionSeed, wallet } from "./main.js";

const cosmos_sig = "c5uzRIuxO91I8BYxJ8CREuHoDkhH4wJXa5W8mng/gbhXnhAQQ9WEYsGkJHtEK8Ppnt6rXG/IcvL7x7AdBbmpfw==";
const eth_pubkey = "0x254768D47Cf8958a68242ce5AA1aDB401E1feF2B";
const eth_sig = "0xf7992bd3f7cb1030b5d69d3326c6e2e28bfde2e38cbb8de753d1be7b5a5ecbcf2d3eccd3fe2e1fccb2454c47dcb926bd047ecf5b74c7330584cbfd619248de811b"
const pubkey = { type: "tendermint/PubKeySecp256k1", value: "AyZtxhLgis4Ec66OVlKDnuzEZqqV641sm46R3mbE2cpO" }
const partial_tree = ['fbff7c66d3f610bcf8223e61ce12b10bb64a3433622ff39af83443bcec78920a']
const permitKey = ""

let create_account = async () => {
  const addressProofMsg = {
    address: wallet.address,
    amount: "420",
    contract: secretHeadstashContractAddr,
    index: 1,
    key: permitKey,
  }
  // encode memo to base64 string
  const encoded_memo = Buffer.from(JSON.stringify(addressProofMsg)).toString('base64');

  const fillerMsg = {
    coins: [],
    contract: secretHeadstashContractAddr,
    execute_msg: {},
    sender: wallet.address,
  }

  // account
  const permitParams = {
    params: fillerMsg,
    signature: {
      pub_key: pubkey,
      signature: cosmos_sig,
    },
    chain_id: chain_id,
    memo: encoded_memo,
  }

  const createAccount = {
    account: {
      addresses: [permitParams],
      eth_pubkey: eth_pubkey,
      eth_sig: eth_sig.slice(2),
      partial_tree: partial_tree,
    }
  }

  const tx = await secretjs.tx.compute.executeContract({
    sender: wallet.address,
    contract_address: secretHeadstashContractAddr,
    msg: createAccount,
    code_hash: scrtHeadstashCodeHash,
  },
    {
      gasLimit: 400_000,
      explicitSignerData: {
        accountNumber: 22761,
        sequence: 191,
        chainId: "pulsar-3"
      }
    })

  console.log(tx);
}
export {create_account}



