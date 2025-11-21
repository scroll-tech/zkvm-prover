extern crate ceno_rt;

// use ceno_crypto::secp256k1;
use ceno_crypto::ceno_crypto;
use ceno_crypto::secp256k1::secp256k1_ecrecover;
use rkyv::Archived;
use scroll_zkvm_types_chunk::{Address, ChunkWitness, alloy_consensus, execute, revm_precompile};
use scroll_zkvm_types_chunk::alloy_consensus::private::alloy_primitives;
use scroll_zkvm_types_chunk::alloy_consensus::private::alloy_primitives::{address, b256, hex, Signature, B256};

ceno_crypto!(
    revm_precompile = revm_precompile,
    alloy_consensus = alloy_consensus,
    address_type = Address,
);



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

    // test alloy call directly
    let signature_hash = b256!("4da82bc12df24f77a4a136cbf0050cecfe8079e484a1754a7725bf96628d8c08");
    let signature = Signature::from_raw(&hex::decode("0xb44fa252d86bd16e029b5d5241bf382829db0339bb0f571d2444dc18b342e8cb324a5412cc85018661cdc8749fddd721b8db803fbad4a163ec9a152d1cad41851c").unwrap()).unwrap();

    let _result = alloy_consensus::crypto::secp256k1::recover_signer(&signature, signature_hash);

    // secp256k1_ecrecover
    // let witness_bytes: &Archived<Vec<u8>> = ceno_rt::read();
    //
    // let config = bincode::config::standard();
    // let (witness, _): (ChunkWitness, _) = bincode::serde::decode_from_slice(witness_bytes, config)
    //     .expect("ChunkCircuit: deserialisation of witness bytes failed");
    //
    // // let _fork_name = witness.fork_name;
    // let _chunk_info = execute(witness).expect("execution failed");

    // let pi_hash = (chunk_info, fork_name).pi_hash();
    // ceno_rt::commit(&pi_hash);
}
