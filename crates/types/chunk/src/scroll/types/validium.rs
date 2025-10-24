#![allow(non_snake_case)]

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::{SolCall, sol};
use sbv_primitives::types::consensus::TxL1Message;

pub use ecies::SecretKey;

sol! {
    #[derive(Debug)]
    function relayMessage(
        address sender,
        address target,
        uint256 value,
        uint256 messageNonce,
        bytes message
    );

    #[derive(Debug)]
    function finalizeDepositERC20(
        address token,
        address l2Token,
        address from,
        address to,
        uint256 amount,
        bytes l2Data
    );

    #[derive(Debug)]
    function finalizeDepositERC20Encrypted(
        address token,
        address l2Token,
        address from,
        bytes to,
        uint256 amount,
        bytes l2Data
    );

}

#[derive(Debug, thiserror::Error)]
pub enum ValidiumError {
    #[error(transparent)]
    Decode(#[from] alloy_sol_types::Error),
    #[error(transparent)]
    Decrypt(#[from] ecies::DecryptError),
    #[error("Invalid target address")]
    InvalidTarget,
}

pub fn decrypt(tx: &TxL1Message, secret_key: &SecretKey) -> Result<TxL1Message, ValidiumError> {
    Ok(TxL1Message {
        queue_index: tx.queue_index,
        gas_limit: tx.gas_limit,
        to: tx.to,
        value: tx.value,
        sender: tx.sender,
        input: decrypt_data(&tx.input, secret_key)?,
    })
}

fn decrypt_data(data: &Bytes, secret_key: &SecretKey) -> Result<Bytes, ValidiumError> {
    if data.starts_with(&relayMessageCall::SELECTOR) {
        let mut msg: relayMessageCall = relayMessageCall::abi_decode(data.as_ref())?;
        if msg
            .message
            .starts_with(&finalizeDepositERC20EncryptedCall::SELECTOR)
        {
            msg.message = decrypt_message(&msg.message, secret_key)?;
            return Ok(Bytes::from(msg.abi_encode()));
        }
    }
    Ok(data.clone())
}

fn decrypt_message(message: &Bytes, secret_key: &SecretKey) -> Result<Bytes, ValidiumError> {
    if message.starts_with(&finalizeDepositERC20EncryptedCall::SELECTOR) {
        let finalizeDepositERC20EncryptedCall {
            token,
            l2Token,
            from,
            to,
            amount,
            l2Data,
        } = finalizeDepositERC20EncryptedCall::abi_decode(message.as_ref())?;
        let to = secret_key.try_decrypt(to.as_ref())?;
        let to = Address::try_from(to.as_slice()).map_err(|_| ValidiumError::InvalidTarget)?;
        return Ok(Bytes::from(
            finalizeDepositERC20Call {
                token,
                l2Token,
                from,
                to,
                amount,
                l2Data,
            }
            .abi_encode(),
        ));
    }

    Ok(message.clone())
}
