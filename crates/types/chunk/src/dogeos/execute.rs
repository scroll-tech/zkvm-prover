use bridge_adapters_zk::{StepInputEnvelope, ZkVerifierExt};
use bridge_steps_deposit::{HeaderVerifier, MidstateVerifier};
use itertools::Itertools;
use sbv_primitives::types::consensus::TxL1Message;
use types_base::public_inputs::dogeos::chunk::DogeOsChunkInfo;
use super::witness::DogeOsChunkWitness;

pub fn execute(witness: DogeOsChunkWitness) -> Result<DogeOsChunkInfo, String>  {
    let l1_messages = witness
        .inner.blocks.iter()
        .flat_map(|block| block.transactions.iter())
        .filter_map(|tx| tx.as_l1_message())
        .map(|tx| tx.inner().clone())
        .collect::<Vec<TxL1Message>>();

    let chunk_info = crate::scroll::execute(witness.inner)?;

    verify_deposits(
        &witness.verifier_context,
        &witness.header,
        &witness.midstate,
        &l1_messages
    )?;

    let start_blockhash = witness
        .header
        .statement
        .start_blockhash
        .expect("start_blockhash must be present in header statement");
    let end_blockhash = witness
        .header
        .statement
        .end_blockhash
        .expect("end_blockhash must be present in header statement");
    Ok(DogeOsChunkInfo {
        inner: chunk_info,
        // Other DogeOs-specific fields can be initialized here
        start_blockhash,
        end_blockhash,
    })
}

fn verify_deposits(
    verifier_context: &bridge_core::VerifierContext,
    header_envelope: &StepInputEnvelope<HeaderVerifier>,
    midstate_envelope: &StepInputEnvelope<MidstateVerifier>,
    l1_messages: &[TxL1Message],
) -> Result<(), String> {
    HeaderVerifier.verify_envelope(&header_envelope, &verifier_context)
        .map_err(|e| format!("dogeos deposit header verification failed: {e}"))?;
    assert_eq!(header_envelope.statement, midstate_envelope.statement.header_range);
    MidstateVerifier.verify_envelope(&midstate_envelope, &verifier_context)
        .map_err(|e| format!("dogeos deposit midstate verification failed: {e}"))?;

    for (deposit, l1_message) in midstate_envelope.statement.expected_deposits.iter().zip_eq(l1_messages) {
        l1_message.input

    }

    Ok(())

}
