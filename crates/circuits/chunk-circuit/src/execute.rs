use std::mem::ManuallyDrop;

use sbv::{
    core::{ChunkInfo as SbvChunkInfo, EvmDatabase, EvmExecutor},
    primitives::{
        Block, BlockWitness, RecoveredBlock,
        chainspec::{Chain, get_chain_spec},
        ext::{BlockWitnessChunkExt, TxBytesHashExt},
    },
};
use scroll_zkvm_circuit_input_types::chunk::{ChunkInfo, make_providers};

pub fn execute<W: BlockWitness>(witnesses: &[W]) -> ChunkInfo {
    assert!(
        !witnesses.is_empty(),
        "At least one witness must be provided in chunk mode"
    );
    assert!(
        witnesses.has_same_chain_id(),
        "All witnesses must have the same chain id in chunk mode"
    );
    assert!(
        witnesses.has_seq_block_number(),
        "All witnesses must have sequential block numbers in chunk mode"
    );

    let blocks = witnesses
        .iter()
        .map(|w| w.build_reth_block())
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to build reth block")
        .leak() as &'static [RecoveredBlock<Block>];

    let sbv_chunk_info = SbvChunkInfo::from_blocks(
        witnesses[0].chain_id(),
        witnesses[0].pre_state_root(),
        blocks,
    );

    let chain_spec = get_chain_spec(Chain::from_id(sbv_chunk_info.chain_id()))
        .expect("failed to get chain spec");

    let (code_db, nodes_provider, block_hashes) = make_providers(witnesses);
    let nodes_provider = ManuallyDrop::new(nodes_provider);

    let mut db = ManuallyDrop::new(
        EvmDatabase::new_from_root(
            code_db,
            sbv_chunk_info.prev_state_root(),
            &nodes_provider,
            block_hashes,
        )
        .expect("failed to create EvmDatabase"),
    );
    for block in blocks.iter() {
        let output = ManuallyDrop::new(
            EvmExecutor::new(chain_spec.clone(), &db, block)
                .execute()
                .expect("failed to execute block"),
        );
        db.update(&nodes_provider, output.state.state.iter())
            .expect("failed to update db");
    }

    let post_state_root = db.commit_changes();
    assert_eq!(
        sbv_chunk_info.post_state_root(),
        post_state_root,
        "state root mismatch"
    );

    let withdraw_root = db.withdraw_root().expect("failed to get withdraw root");

    let mut rlp_buffer = ManuallyDrop::new(Vec::with_capacity(2048));
    let tx_data_digest = blocks
        .iter()
        .flat_map(|b| b.body().transactions.iter())
        .tx_bytes_hash_in(rlp_buffer.as_mut());

    openvm::io::println(format!("withdraw_root = {:?}", withdraw_root));
    openvm::io::println(format!("tx_bytes_hash = {:?}", tx_data_digest));

    ChunkInfo {
        chain_id: sbv_chunk_info.chain_id(),
        prev_state_root: sbv_chunk_info.prev_state_root(),
        post_state_root: sbv_chunk_info.post_state_root(),
        withdraw_root,
        data_hash: sbv_chunk_info.data_hash(),
        tx_data_digest,
    }
}
