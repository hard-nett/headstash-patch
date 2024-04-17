import { MsgExecuteContract, fromBase64, toUtf8 } from "secretjs";
import { encodeJsonToB64 } from "@shadeprotocol/shadejs";
import { chain_id, scrtHeadstashCodeHash, secretHeadstashContractAddr, secretjs, txEncryptionSeed, wallet, permitKey, pubkey, cosmos_sig, eth_pubkey, eth_sig, partial_tree } from "./main.js";

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
      // explicitSignerData: {
      //   accountNumber: 22761,
      //   sequence: 191,
      //   chainId: "pulsar-3"
      // }
    })

  console.log(tx);
}
export { create_account }



