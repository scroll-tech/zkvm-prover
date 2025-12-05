use alloy_primitives::U256;
use alloy_sol_types::SolCall;
use bridge_adapters_zk::{StepInputEnvelope, ZkVerifierExt};
use bridge_steps_deposit::{HeaderVerifier, MidstateVerifier};
use itertools::Itertools;
use sbv_primitives::types::consensus::TxL1Message;
use types_base::public_inputs::dogeos::chunk::DogeOsChunkInfo;
use crate::dogeos::types::{handleL1MessageCall, MOAT_CONTRACT_ADDRESS};
use crate::scroll::relayMessageCall;
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

    for (deposit, l1_message) in midstate_envelope
        .statement
        .expected_deposits
        .iter()
        .zip_eq(l1_messages) {
        let relay_call: relayMessageCall = relayMessageCall::abi_decode(l1_message.input.as_ref())
            .map_err(|e| format!("dogeos relay call decode failed: {e}"))?;
        // -- l1 message checks --
        // possibly redundant checks, kept for clarity

        // ref: https://github.com/DogeOS69/dogeos-core/blob/73ff17223d3bdb473b164bd87798207b5df7275e/crates/l1_interface/src/state/log_generator.rs#L531-L552
        // assert_eq!(l1_message.sender, aliased_l1_messenger);

        // ref:
        // - https://github.com/DogeOS69/dogeos-core/blob/73ff17223d3bdb473b164bd87798207b5df7275e/crates/l1_interface/src/state/log_generator.rs#L507-L512
        // - https://github.com/DogeOS69/dogeos-core/blob/73ff17223d3bdb473b164bd87798207b5df7275e/crates/l1_interface/src/state/log_generator.rs#L556
        // assert_eq!(l1_message.to, messenger_target);

        // ref: https://github.com/DogeOS69/dogeos-core/blob/73ff17223d3bdb473b164bd87798207b5df7275e/crates/l1_interface/src/state/log_generator.rs#L557
        // assert_eq!(l1_message.value, U256::ZERO);

        // -- relay call checks --

        // ref:
        // - https://github.com/DogeOS69/dogeos-core/blob/73ff17223d3bdb473b164bd87798207b5df7275e/crates/l1_interface/src/state/log_generator.rs#L490
        // - https://github.com/DogeOS69/dogeos-core/blob/d0f71b8596f116d7fef5859c5a44eb385bf55499/crates/l1_interface/src/deposit/calldata_builder.rs#L102
        assert_eq!(relay_call.sender, deposit.txid[..20], "dogeos synthetic relay call sender mismatch");

        // ref: https://github.com/DogeOS69/dogeos-core/blob/d0f71b8596f116d7fef5859c5a44eb385bf55499/crates/l1_interface/src/deposit/calldata_builder.rs#L103
        assert_eq!(relay_call.target, MOAT_CONTRACT_ADDRESS, "dogeos relay call target mismatch");

        // ref: https://github.com/DogeOS69/dogeos-core/blob/73ff17223d3bdb473b164bd87798207b5df7275e/crates/l1_interface/src/state/log_generator.rs#L503
        let amount = U256::from(bridge_transforms::convert_doge_to_eth_units(deposit.amount_sats));
        // ref: https://github.com/DogeOS69/dogeos-core/blob/d0f71b8596f116d7fef5859c5a44eb385bf55499/crates/l1_interface/src/deposit/calldata_builder.rs#L104
        assert_eq!(relay_call.value, amount, "dogeos relay call amount mismatch");
        // nonce/queueIndex check is skipped, as it's guaranteed by rolling hash

        let moat_call: handleL1MessageCall = handleL1MessageCall::abi_decode(relay_call.message.as_ref())
            .map_err(|e| format!("dogeos moat call decode failed: {e}"))?;

        // -- moat call checks --

        // ref:
        // - https://github.com/DogeOS69/dogeos-core/blob/73ff17223d3bdb473b164bd87798207b5df7275e/crates/l1_interface/src/state/log_generator.rs#L500
        // - https://github.com/DogeOS69/dogeos-core/blob/d0f71b8596f116d7fef5859c5a44eb385bf55499/crates/l1_interface/src/deposit/calldata_builder.rs#L96
        assert_eq!(moat_call.target, deposit.evm_recipient, "dogeos deposit recipient mismatch");

        // ref:
        // - https://github.com/DogeOS69/dogeos-core/blob/73ff17223d3bdb473b164bd87798207b5df7275e/crates/l1_interface/src/state/log_generator.rs#L514-L518
        // - https://github.com/DogeOS69/dogeos-core/blob/d0f71b8596f116d7fef5859c5a44eb385bf55499/crates/l1_interface/src/deposit/calldata_builder.rs#L96
        assert_eq!(moat_call.depositID, deposit.txid);
    }

    Ok(())

}
