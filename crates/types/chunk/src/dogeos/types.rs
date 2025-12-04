use alloy_primitives::{address, Address};
use alloy_sol_types::{sol, SolCall};

sol! {
    /// Moat.handleL1Message function
    /// This is the final L2 execution target
    /// Signature: handleL1Message(address,bytes32)
    function handleL1Message(
        address target,
        bytes32 depositID
    ) external;
}

pub const MOAT_CONTRACT_ADDRESS: Address = address!("0xcccccccccccccccccccccccccccccccccccccccc");

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, U256};
    use crate::dogeos::types::{handleL1MessageCall};
    use crate::scroll::relayMessageCall;

    fn create_queue_transaction_calldata(
        sender: Address,
        to: Address,
        value: U256,
        nonce: u64,
        deposit_id: B256,
    ) -> Vec<u8> {
        // Step 1: Create Moat.handleL1Message calldata (innermost call)
        // This is what will ultimately be executed when relayMessage calls the Moat contract
        let moat_call = handleL1MessageCall { target: to, depositID: deposit_id };
        let moat_calldata = moat_call.abi_encode();

        // Step 2: Create L2ScrollMessenger.relayMessage calldata (what gets queued)
        // This is the call that L1MessageQueue stores and L2ScrollMessenger will execute
        let relay_call = relayMessageCall {
            sender,                            // Original L1 sender
            target: MOAT_CONTRACT_ADDRESS,     // Moat contract (intermediate target)
            value,                             // ETH value to transfer
            messageNonce: U256::from(nonce),   // Queue index as nonce
            message: moat_calldata.into(),     // Nested Moat.handleL1Message call
        };

        relay_call.abi_encode()
    }

}
