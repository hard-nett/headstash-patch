import { Wallet, SecretNetworkClient, EncryptionUtilsImpl, fromUtf8, MsgExecuteContract, MsgExecuteContractResponse, fromBase64, toBase64 } from "secretjs";
import * as fs from "fs";

const wallet = new Wallet(
  "goat action fuel major strategy adult kind sand draw amazing pigeon inspire antenna forget six kiss loan script west jaguar again click review have"
);

const txEncryptionSeed = EncryptionUtilsImpl.GenerateNewSeed();

const scrt20codeId = 5697;
const scrt20CodeHash = "c74bc4b0406507257ed033caa922272023ab013b0c74330efc16569528fa34fe";
const secretTerpContractAddr = "secret1c3lj7dr9r2pe83j3yx8jt5v800zs9sq7we6wrc";
const secretThiolContractAddr = "secret1umh28jgcp0g9jy3qc29xk42kq92xjrcdfgvwdz";

const scrtHeadstashCodeId = 6272;
const scrtHeadstashCodeHash = "f87c7817a43ca68c99fcf425eb1f255393df813c9955501d89a24d09b9967512";
const scrtHeadstashContractAddr = "secret1l97vzuf8lsr0kdvepxqut9w4mf2v49vh35zqxp";

const viewingKey = "eretskeretjableret"

const eth_pubkey = "0x254768D47Cf8958a68242ce5AA1aDB401E1feF2B";


// client
const secretjs = new SecretNetworkClient({
  chainId: "pulsar-3",
  url: "https://api.pulsar.scrttestnet.com",
  wallet: wallet,
  walletAddress: wallet.address,
  txEncryptionSeed: txEncryptionSeed
});

// filler message of AddressProofPermit
const fillerMsg = {
  coins: [],
  contract: scrtHeadstashContractAddr,
  eth_pubkey: eth_pubkey,
  execute_msg: {},
  sender: wallet.address,
}

// data to be encoded in memo of AddressProofPermit
const addrProofMsg = {
  address: wallet.address,
  amount: "420",
  contract: scrtHeadstashContractAddr,
  index: 0,
  key: "eretskeretjableret"
}

// Convert JSON object to JSON string
const addrProofMsgJson = JSON.stringify(addrProofMsg);

// signature documentate as defined here: 
// https://github.com/securesecrets/shade/blob/77abdc70bc645d97aee7de5eb9a2347d22da425f/packages/shade_protocol/src/signature/mod.rs#L100


const encodedAddrProofMsg = toBase64(addrProofMsgJson);

const addMinterMsg = new MsgExecuteContract({
  sender: "secret13uazul89dp0lypuxcz0upygpjy0ftdah4lnrs4",
  contract_address: scrtHeadstashContractAddr,
  code_hash: scrtHeadstashCodeHash, // optional but way faster
  msg: {
    account: {
      eth_pubkey: eth_pubkey,
      addresses: [{
        params: {
          account_number: 0,
          chain_id: "pulsar-3"
        },
        memo: "eyJhZGRyZXNzIjoic2VjcmV0MTN1YXp1bDg5ZHAwbHlwdXhjejB1cHlncGp5MGZ0ZGFoNGxucnM0IiwiYW1vdW50IjoiNDIwIiwiY29udHJhY3QiOiJzZWNyZXQxbDk3dnp1Zjhsc3Iwa2R2ZXB4cXV0OXc0bWYydjQ5dmgzNXpxeHAiLCJpbmRleCI6MCwia2V5IjoiZXJldHNrZXJldGphYmxlcmV0In0=",
        signature: {
          pub_key: {
            type: "tendermint/PubKeySecp256k1",
            value: "AyZtxhLgis4Ec66OVlKDnuzEZqqV641sm46R3mbE2cpO",
          },
          signature: fromBase64("tTjK3Mf4dpQrSQT2hsqXn+pgeXhVjQhw2EXP5N50uhBJ0kpV9IS5uyfo+PHvB20CVHMwux9leaByfXI3T6PD6A==")
        },
        //  account_number: Option<Uint128>,
        //  chain_id: Option<String>,
        //  sequence: Option<Uint128>,
        //  memo: Option<String>,
      }],
    }
  },
  sent_funds: [], // optional
});

const tx = await secretjs.tx.broadcast([addMinterMsg], {
  gasLimit: 200_000,
});

// console.log(addrProofMsgJson);
console.log(tx);

// let create_account = async () => {

//   let tx = await secretjs.tx.broadcast([], { gasLimit: 400_000, }
//   );
// };


