extern crate ceno_rt;

// use ceno_crypto::secp256k1;
use ceno_crypto::ceno_crypto;
use ceno_crypto::secp256k1::secp256k1_ecrecover;
use rkyv::Archived;
use scroll_zkvm_types_chunk::{Address, ChunkWitness, alloy_consensus, execute, revm_precompile, TxEnvelope};
use scroll_zkvm_types_chunk::sbv_primitives::{address, b256, Signature, B256};
use scroll_zkvm_types_chunk::alloy_consensus::transaction::SignerRecoverable;
use scroll_zkvm_types_chunk::sbv_primitives::alloy_primitives::hex;

ceno_crypto!(
    revm_precompile = revm_precompile,
    alloy_consensus = alloy_consensus,
    address_type = Address,
);


static TX: &str = r#"{
  "Legacy": {
    "signature": {
      "r": "0x10f71f4be1d573ca7d686d9c29c3165b9e2725e9dee8296eacb12cf4c27b24b4",
      "s": "0x13e4d58bfaf75faf85225f49fe8caa7f81a36483a05b13d30020b341fdfc0521",
      "yParity": "0x0",
      "v": "0x0"
    },
    "transaction": {
      "chain_id": "0x82750",
      "nonce": 20481,
      "gas_price": 120106,
      "gas_limit": 777624,
      "to": "0xc9c35e593842c3d5e71304b2291e204583226e2a",
      "value": "0x0",
      "input": "0x412658e5000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000001260000000000000000000000000000000000000000020027004f00cd00f900fd0101010501150125530000000000000000000000000000000000000406efdbff2a14a7c8e15944d1f4a48f9f95f663a4005300903c96cfa2a369ec67a93c324a35e693fbeea11c0594f4b328cd17d59be12040a2d03d656bdbca3206bff4b328cd17d59be12040a2d03d656bdbca3206bf3c814a23b053fd0f102aeeda0459215c2444799c7006efdbff2a14a7c8e15944d1f4a48f9f95f663a4530000000000000000000000000000000000000400d100e5f4b328cd17d59be12040a2d03d656bdbca3206bfbf0f198847c0020dbb462971eedbfdcf950b955200d100e500010005000000000000000000000000000a91950b6ebacc00000000000000000000000f8866df92010000000000000000000000000000000000000000000000000000"
    }
  }
}"#;

fn main() {
    CenoCrypto::install();


    // test ceno precompile call
    // let (sig, recid, tx_hash, signer) = (
    //     &hex!(
    //         "004a0ac1306d096c06fb77f82b76f43fb2459638826f4846444686b3036b9a4b3d6bf124bf22f23b851adfa2c4bdc670b4ecb5129186a4e89032916a77a56b90"
    //     ),
    //     0,
    //     b256!("83e5e11daa2d14736ab1d578c41250c6f6445782c215684a18f67b44686ccb90"),
    //     address!("0a6f0ed4896be1caa9e37047578e7519481f22ea"),
    // );
    //
    // let recovered = secp256k1_ecrecover(sig.try_into().unwrap(), recid, &tx_hash.0).unwrap();
    // assert_eq!(&recovered[12..], &signer.0);

    // // test alloy call directly
    // let signature_hash = b256!("4da82bc12df24f77a4a136cbf0050cecfe8079e484a1754a7725bf96628d8c08");
    // let signature = Signature::from_raw(&hex::decode("0xb44fa252d86bd16e029b5d5241bf382829db0339bb0f571d2444dc18b342e8cb324a5412cc85018661cdc8749fddd721b8db803fbad4a163ec9a152d1cad41851c").unwrap()).unwrap();
    //
    // let _result = alloy_consensus::crypto::secp256k1::recover_signer(&signature, signature_hash);

    // secp256k1_ecrecover
    let witness_bytes: &Archived<Vec<u8>> = ceno_rt::read();

    let config = bincode::config::standard();
    let (witness, _): (ChunkWitness, _) = bincode::serde::decode_from_slice(witness_bytes, config)
        .expect("ChunkCircuit: deserialisation of witness bytes failed");
    witness.blocks[0].transactions[0].recover_signer().ok();

    // // let _fork_name = witness.fork_name;
    // let _chunk_info = execute(witness).expect("execution failed");

    // let pi_hash = (chunk_info, fork_name).pi_hash();
    // ceno_rt::commit(&pi_hash);
}
