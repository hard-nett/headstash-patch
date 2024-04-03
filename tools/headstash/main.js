import { Wallet, SecretNetworkClient, EncryptionUtilsImpl, fromUtf8, MsgExecuteContractResponse } from "secretjs";
import * as fs from "fs";
import {encodedAddrProofMsg} from "./account"

// wallet
const wallet = new Wallet("<YOUR_MNEMONIC_SEED>");
const txEncryptionSeed = EncryptionUtilsImpl.GenerateNewSeed();
const contract_wasm = fs.readFileSync("./target/wasm32-unknown-unknown/release/airdrop.wasm");

// snip-20
const scrt20codeId = 5697;
const scrt20CodeHash = "c74bc4b0406507257ed033caa922272023ab013b0c74330efc16569528fa34fe";
const secretTerpContractAddr = "secret1c3lj7dr9r2pe83j3yx8jt5v800zs9sq7we6wrc";
const secretThiolContractAddr = "secret1umh28jgcp0g9jy3qc29xk42kq92xjrcdfgvwdz";

// airdrop contract
const scrtHeadstashCodeId = 6294;
const scrtHeadstashCodeHash = "8f1816b524f9246e421503c9e764fbfdec615e2c52f258286ffebc09798bbe6e";
const secretHeadstashContractAddr = "secret1r8hpc5uvykea0hzc92nlfrn60rwlc02rsa4fyv";

const secretjs = new SecretNetworkClient({
  chainId: "pulsar-3",
  url: "https://api.pulsar.scrttestnet.com",
  wallet: wallet,
  walletAddress: wallet.address,
  txEncryptionSeed: txEncryptionSeed
});

let upload_contract = async () => {
  let tx = await secretjs.tx.compute.storeCode(
    {
      sender: wallet.address,
      wasm_byte_code: contract_wasm,
      source: "",
      builder: "",
    },
    {
      gasLimit: 4_000_000,
    }
  );

  const codeId = Number(
    tx.arrayLog.find((log) => log.type === "message" && log.key === "code_id")
      .value
  );

  console.log("codeId: ", codeId);
  // contract hash, useful for contract composition
  const contractCodeHash = (await secretjs.query.compute.codeHashByCodeId({ code_id: codeId })).code_hash;
  console.log(`Contract hash: ${contractCodeHash}`);
}
let instantiate_headstash_contract = async () => {
  let initMsg = {
    admin: wallet.address,
    dump_address: wallet.address,
    airdrop_token: {
      address: secretTerpContractAddr,
      code_hash: scrt20CodeHash
    },
    airdrop_2: {
      address: secretThiolContractAddr,
      code_hash: scrt20CodeHash
    },
    airdrop_amount: "840",
    start_date: null,
    end_date: null,
    decay_start: null,
    max_amount: "420",
    merkle_root: "d599867bdb2ade1e470d9ec9456490adcd9da6e0cfd8f515e2b95d345a5cd92f",
    total_accounts: 2,
    claim_msg_plaintext: "{wallet}",
    query_rounding: "1"
  };

  let tx = await secretjs.tx.compute.instantiateContract(
    {
      code_id: scrtHeadstashCodeId,
      sender: wallet.address,
      code_hash: scrtHeadstashCodeHash,
      init_msg: initMsg,
      label: "Secret Headstash Patch " + Math.ceil(Math.random() * 10000),
    },
    {
      gasLimit: 400_000,
    }
  );

  console.log(tx);
  //Find the contract_address in the logs
  const contractAddress = tx.arrayLog.find(
    (log) => log.type === "message" && log.key === "contract_address"
  ).value;

  console.log(contractAddress);
}
let instantiate_contract = async (name, synbol, supported_denom) => {
  const initMsg = {
    name: "Terp Network Gas Token",
    symbol: "THIOL",
    decimals: 6,
    prng_seed: Buffer.from("dezayum").toString("base64"),
    admin: wallet.address,
    supported_denoms: [supported_denom]
  };
  let tx = await secretjs.tx.compute.instantiateContract(
    {
      code_id: codeId,
      sender: wallet.address,
      code_hash: contractCodeHash,
      init_msg: initMsg,
      label: " Secret Wrapped Terp Network Gas Tokens (THIOL)" + Math.ceil(Math.random() * 10000),
    },
    {
      gasLimit: 400_000,
    }
  );
  //Find the contract_address in the logs
  const contractAddress = tx.arrayLog.find(
    (log) => log.type === "message" && log.key === "contract_address"
  ).value;

  console.log(contractAddress);
};


// Process command line arguments
const args = process.argv.slice(2);

// Determine which function to run based on the first argument
if (args.length < 1) {
  console.error('Invalid option. Please provide -s to store the contract, or -i to instantiate the contract, followed by expected values [name] [symbol] [ibc-hash].');
} else if (args[0] === '-s') {
  upload_contract(args[1]);
} else if (args[0] === '-h') {
  instantiate_headstash_contract();
} else if (args[0] === '-a') {

} else if (args[0] === '-i') {
  if (args.length < 4) {
    console.error('Usage: -i name symbol [supported_denoms]');
    process.exit(1);
  }
  const [, name, symbol, supported_denoms] = args; // Extracting values
  instantiate_contract(name, symbol, supported_denoms)
    .then(() => {
      console.log("Upload completed!");
    })
    .catch((error) => {
      console.error("Upload failed:", error);
    });
} else {
  console.error('Invalid option. Please provide -s to store the contract, or -i to instantiate the contract, followed by expected values [name] [symbol] [ibc-hash].');
}