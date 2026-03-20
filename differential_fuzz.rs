//! Differential test: compare Scroll's OpenVM crypto against revm's crypto.
//! Run from zkvm-prover root: cargo test --test differential_fuzz --features "scroll host" -- --nocapture

use hex_literal::hex;
use scroll_zkvm_types_chunk::crypto::Crypto;
use sbv_primitives::types::revm::precompile::{self, PrecompileError};
use revm_scroll::ScrollSpecId;
use revm_scroll::precompile::ScrollPrecompileProvider;

// Precompile addresses
const ECADD: sbv_primitives::Address = sbv_primitives::address!("0000000000000000000000000000000000000006");
const ECMUL: sbv_primitives::Address = sbv_primitives::address!("0000000000000000000000000000000000000007");
const ECPAIRING: sbv_primitives::Address = sbv_primitives::address!("0000000000000000000000000000000000000008");

const P_MINUS_2: [u8; 32] = hex!("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45");
const BN254_R: [u8; 32] = hex!("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");

fn run_scroll_precompile(addr: &sbv_primitives::Address, input: &[u8]) -> Result<Vec<u8>, String> {
    let provider = ScrollPrecompileProvider::new_with_spec(ScrollSpecId::GALILEO);
    let precompiles = provider.precompiles();
    let precompile = precompiles.get(addr).ok_or("not found")?;
    match precompile.execute(input, u64::MAX) {
        Ok(output) => Ok(output.bytes.to_vec()),
        Err(e) => Err(format!("{:?}", e)),
    }
}

fn run_zkvm_ecadd(p1: &[u8], p2: &[u8]) -> Result<[u8; 64], String> {
    // Install the zkVM crypto provider
    let crypto = Crypto;
    precompile::Crypto::bn254_g1_add(&crypto, p1, p2)
        .map_err(|e| format!("{:?}", e))
}

fn run_zkvm_ecmul(point: &[u8], scalar: &[u8]) -> Result<[u8; 64], String> {
    let crypto = Crypto;
    precompile::Crypto::bn254_g1_mul(&crypto, point, scalar)
        .map_err(|e| format!("{:?}", e))
}

fn run_zkvm_pairing(pairs: Vec<(&[u8], &[u8])>) -> Result<bool, String> {
    let crypto = Crypto;
    precompile::Crypto::bn254_pairing_check(&crypto, &pairs)
        .map_err(|e| format!("{:?}", e))
}

fn compare(name: &str, revm_result: Result<Vec<u8>, String>, zkvm_result: Result<Vec<u8>, String>) {
    match (&revm_result, &zkvm_result) {
        (Ok(a), Ok(b)) => {
            if a == b {
                println!("  {name}: MATCH");
            } else {
                println!("  {name}: *** DIVERGENCE ***");
                println!("    revm: {:02x?}", &a[..a.len().min(32)]);
                println!("    zkvm: {:02x?}", &b[..b.len().min(32)]);
                panic!("DIVERGENCE FOUND: {name}");
            }
        }
        (Err(e1), Err(e2)) => {
            println!("  {name}: MATCH (both error: {e1})");
        }
        (Ok(_), Err(e)) => {
            println!("  {name}: *** DIVERGENCE (revm OK, zkvm ERR: {e}) ***");
            panic!("DIVERGENCE FOUND: {name}");
        }
        (Err(e), Ok(_)) => {
            println!("  {name}: *** DIVERGENCE (revm ERR: {e}, zkvm OK) ***");
            panic!("DIVERGENCE FOUND: {name}");
        }
    }
}

#[test]
fn differential_ecadd() {
    println!("=== Differential ecAdd ===");

    let cases: Vec<(&str, [u8; 64], [u8; 64])> = vec![
        ("inf + inf", [0u8; 64], [0u8; 64]),
        ("P + O", {
            let mut p = [0u8; 64]; p[31]=1; p[63]=2;
            (p, [0u8; 64])
        }.into()),
        ("O + P", {
            let mut p = [0u8; 64]; p[31]=1; p[63]=2;
            ([0u8; 64], p)
        }.into()),
        ("P + P", {
            let mut p = [0u8; 64]; p[31]=1; p[63]=2;
            (p, p)
        }.into()),
        ("P + (-P)", {
            let mut p1 = [0u8; 64]; p1[31]=1; p1[63]=2;
            let mut p2 = [0u8; 64]; p2[31]=1; p2[32..64].copy_from_slice(&P_MINUS_2);
            (p1, p2)
        }.into()),
    ];

    for (name, p1, p2) in &cases {
        let mut revm_input = Vec::new();
        revm_input.extend_from_slice(p1);
        revm_input.extend_from_slice(p2);

        let revm_result = run_scroll_precompile(&ECADD, &revm_input);
        let zkvm_result = run_zkvm_ecadd(p1, p2).map(|r| r.to_vec());
        compare(name, revm_result, zkvm_result);
    }
}

#[test]
fn differential_ecmul() {
    println!("=== Differential ecMul ===");

    let mut gen = [0u8; 64];
    gen[31] = 1; gen[63] = 2;

    let cases: Vec<(&str, [u8; 64], [u8; 32])> = vec![
        ("P*0", (gen, [0u8; 32]).into()),
        ("P*1", { let mut s = [0u8; 32]; s[31]=1; (gen, s) }.into()),
        ("P*r", (gen, BN254_R).into()),
        ("O*5", { let mut s = [0u8; 32]; s[31]=5; ([0u8; 64], s) }.into()),
        ("P*max", { (gen, [0xFF; 32]) }.into()),
    ];

    for (name, point, scalar) in &cases {
        let mut revm_input = Vec::new();
        revm_input.extend_from_slice(point);
        revm_input.extend_from_slice(scalar);

        let revm_result = run_scroll_precompile(&ECMUL, &revm_input);
        let zkvm_result = run_zkvm_ecmul(point, scalar).map(|r| r.to_vec());
        compare(name, revm_result, zkvm_result);
    }
}

fn main() {
    println!("Run with: cargo test --test differential_fuzz --features 'scroll host' -- --nocapture");
}
