extern crate ceno_rt;

// use ceno_crypto::secp256k1;
use ceno_crypto::ceno_crypto;
use rkyv::Archived;
use scroll_zkvm_types_chunk::{Address, ChunkWitness, alloy_consensus, execute, revm_precompile, TxEnvelope};
use scroll_zkvm_types_chunk::sbv_primitives::{address, b256, Signature, B256};
use scroll_zkvm_types_chunk::alloy_consensus::transaction::SignerRecoverable;
use scroll_zkvm_types_chunk::alloy_consensus::{Signed, TxEip1559, TxLegacy};
use scroll_zkvm_types_chunk::revm_precompile::Crypto;
use scroll_zkvm_types_chunk::sbv_primitives::alloy_primitives::hex;

ceno_crypto!(
    revm_precompile = revm_precompile,
    alloy_consensus = alloy_consensus,
    address_type = Address,
);

fn main() {
    CenoCrypto::install();

    // let TX: &str = r#"{
    //   "signature": {
    //     "r": "0xc6b2255c8e2aff3269d38611946d6fef4d51f3c8d325b343c117ca582cef219a",
    //     "s": "0x7a11a261cd796ef059f9c1922882f2f00985d9e255485725e847c004686f6d7f",
    //     "yParity": "0x0",
    //     "v": "0x0"
    //   },
    //   "transaction": {
    //     "Eip1559": {
    //       "chain_id": 1,
    //       "nonce": 0,
    //       "gas_limit": 21000,
    //       "max_fee_per_gas": 2153982416,
    //       "max_priority_fee_per_gas": 2000000000,
    //       "to": "0x7772fe062c2b6ac0c0f83ca4948177be4889b1b3",
    //       "value": "0x5eec17ccacc3d80",
    //       "access_list": [],
    //       "input": "0x"
    //     }
    //   }
    // }"#;

   // let tx: Signed<TxEip1559> = serde_json::from_str(TX).unwrap();
    // tx.recover_signer().ok();
    // test ceno precompile call
    // let (sig, recid, tx_hash, signer) = (
    //     &hex!(
    //         "004a0ac1306d096c06fb77f82b76f43fb2459638826f4846444686b3036b9a4b3d6bf124bf22f23b851adfa2c4bdc670b4ecb5129186a4e89032916a77a56b90"
    //     ),
    //     0,
    //     b256!("83e5e11daa2d14736ab1d578c41250c6f6445782c215684a18f67b44686ccb90"),
    //     address!("0a6f0ed4896be1caa9e37047578e7519481f22ea"),
    // );
    // let try_ceno_crypto = CenoCrypto {};
    // try_ceno_crypto.secp256k1_ecrecover(sig.try_into().unwrap(), recid, &tx_hash.0).unwrap();
    // assert_eq!(&recovered[12..], &signer.0);

    // // test alloy call directly
    // let signature_hash = b256!("4da82bc12df24f77a4a136cbf0050cecfe8079e484a1754a7725bf96628d8c08");
    // let signature = Signature::from_raw(&hex::decode("0xb44fa252d86bd16e029b5d5241bf382829db0339bb0f571d2444dc18b342e8cb324a5412cc85018661cdc8749fddd721b8db803fbad4a163ec9a152d1cad41851c").unwrap()).unwrap();
    // let _result = alloy_consensus::crypto::secp256k1::recover_signer(&signature, signature_hash);

    let witness_bytes: &Archived<Vec<u8>> = ceno_rt::read();

    let config = bincode::config::standard();
    let (witness, _): (ChunkWitness, _) = bincode::serde::decode_from_slice(witness_bytes, config)
        .expect("ChunkCircuit: deserialisation of witness bytes failed");

    // let _fork_name = witness.fork_name;
    let _chunk_info = execute(witness).expect("execution failed");

    // let pi_hash = (chunk_info, fork_name).pi_hash();
    // ceno_rt::commit(&pi_hash);
}
