use sbv_primitives::types::consensus::TxL1Message;
use types_base::public_inputs::dogeos::chunk::DogeOsChunkInfo;
use super::witness::DogeOsChunkWitness;

pub fn execute(witness: DogeOsChunkWitness) -> Result<DogeOsChunkInfo, String>  {
    let _l1_messages = witness
        .inner.blocks.iter()
        .flat_map(|block| block.transactions.iter())
        .filter_map(|tx| tx.as_l1_message())
        .map(|tx| tx.inner().clone())
        .collect::<Vec<TxL1Message>>();

    let chunk_info = crate::scroll::execute(witness.inner)?;

    Ok(DogeOsChunkInfo {
        inner: chunk_info,
        // Other DogeOs-specific fields can be initialized here
        // ...
    })
}
