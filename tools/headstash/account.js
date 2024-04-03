import { Wallet, SecretNetworkClient, EncryptionUtilsImpl, fromUtf8, MsgExecuteContract, MsgExecuteContractResponse, fromBase64, toBase64 } from "secretjs";
import * as fs from "fs";
import { encodeJsonToB64 } from "@shadeprotocol/shadejs";

// wallet
const wallet = new Wallet("<YOUR_MNEMONIC_SEED>");
const txEncryptionSeed = EncryptionUtilsImpl.GenerateNewSeed();

// snip-20
const scrt20codeId = 5697;
const scrt20CodeHash = "c74bc4b0406507257ed033caa922272023ab013b0c74330efc16569528fa34fe";
const secretTerpContractAddr = "secret1c3lj7dr9r2pe83j3yx8jt5v800zs9sq7we6wrc";
const secretThiolContractAddr = "secret1umh28jgcp0g9jy3qc29xk42kq92xjrcdfgvwdz";

// airdrop contract
const scrtHeadstashCodeId = 6294;
const scrtHeadstashCodeHash = "8f1816b524f9246e421503c9e764fbfdec615e2c52f258286ffebc09798bbe6e";
const secretHeadstashContractAddr = "secret1r8hpc5uvykea0hzc92nlfrn60rwlc02rsa4fyv";


const viewingKey = "eretskeretjableret"
const eth_pubkey = "0x254768D47Cf8958a68242ce5AA1aDB401E1feF2B";


// network client
const secretjs = new SecretNetworkClient({
  chainId: "pulsar-3",
  url: "https://api.pulsar.scrttestnet.com",
  wallet: wallet,
  walletAddress: wallet.address,
  txEncryptionSeed: txEncryptionSeed
});

// filler message of AddressProofPermit
const fillerMsg = {
  contract: secretHeadstashContractAddr,
  execute_msg: {},
  sender: wallet.address,
}

// data to be encoded in memo of AddressProofPermit
const addrProofMsg = {
  address: wallet.address,
  amount: 420,
  contract: secretHeadstashContractAddr,
  index: 0,
  key: "eretskeretjableret"
}
// Convert JSON object to JSON string
const addrProofMsgJson = JSON.stringify(addrProofMsg);
const encoded = encodeJsonToB64(addrProofMsgJson);

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
          memo: encoded,
          params: fillerMsg,
          signature: {
            pub_key: {
              type: "tendermint/PubKeySecp256k1",
              value: "AyZtxhLgis4Ec66OVlKDnuzEZqqV641sm46R3mbE2cpO",
            },
            signature: "tTjK3Mf4dpQrSQT2hsqXn+pgeXhVjQhw2EXP5N50uhBJ0kpV9IS5uyfo+PHvB20CVHMwux9leaByfXI3T6PD6A=="
          },
        }
      ],
      eth_pubkey: eth_pubkey
    }
  },
  sent_funds: [], // optional
});

const tx = await secretjs.tx.broadcast([createAccount], {
  gasLimit: 200_000,
});

console.log(tx);



