use super::ChunkWitness;
use sbv_core::verifier;
use sbv_primitives::chainspec::{Chain, get_chain_spec};

pub fn execute(witness: ChunkWitness) -> Result<(), String> {
    let chain = Chain::from_id(witness.blocks[0].chain_id);
    let chain_spec = get_chain_spec(chain).expect("chain spec not found");

    let _ = verifier::run(&witness.blocks, chain_spec).map_err(|e| format!("verify error: {e}"))?;

    Ok(())
}
