use std::mem::ManuallyDrop;

use sbv::{
    core::{EvmDatabase, EvmExecutor},
    primitives::{
        BlockWitness, RecoveredBlock,
        chainspec::{Chain, get_chain_spec_or_build},
        ext::{BlockWitnessChunkExt, TxBytesHashExt},
        types::{ChunkInfoBuilder, reth::Block},
    },
};
use scroll_zkvm_circuit_input_types::chunk::{
    ArchivedChunkWitness, BlockContextV2, ChunkInfo, make_providers,
};

pub fn execute(witness: &ArchivedChunkWitness) -> ChunkInfo {
    assert!(
        !witness.blocks.is_empty(),
        "At least one witness must be provided in chunk mode"
    );
    assert!(
        witness.blocks.has_same_chain_id(),
        "All witnesses must have the same chain id in chunk mode"
    );
    assert!(
        witness.blocks.has_seq_block_number(),
        "All witnesses must have sequential block numbers in chunk mode"
    );

    let blocks = witness
        .blocks
        .iter()
        .map(|w| w.build_reth_block())
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to build reth block")
        .leak() as &'static [RecoveredBlock<Block>];
    let initial_block_number = blocks[0].header().number;


    //let chain_spec = get_chain_spec(Chain::from_id(witness.blocks[0].chain_id()))
    //    .expect("failed to get chain spec");

    // TODO: should not allow such a short cut?
    // use the same code from sbv
    let chain_spec = get_chain_spec_or_build(Chain::from_id(witness.blocks[0].chain_id()), |_spec| {
        #[cfg(feature = "scroll")]
        {
            use sbv::primitives::chainspec::ForkCondition;
            use sbv::primitives::hardforks::ScrollHardfork;
            _spec
                .inner
                .hardforks
                .insert(ScrollHardfork::EuclidV2, ForkCondition::Timestamp(0));
        }
    });

    let (code_db, nodes_provider, block_hashes) = make_providers(&witness.blocks);
    let nodes_provider = ManuallyDrop::new(nodes_provider);

    let prev_state_root = witness.blocks[0].pre_state_root();
    let mut db = ManuallyDrop::new(
        EvmDatabase::new_from_root(code_db, prev_state_root, &nodes_provider, block_hashes)
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

    let withdraw_root = db.withdraw_root().expect("failed to get withdraw root");

    let mut rlp_buffer = ManuallyDrop::new(Vec::with_capacity(2048));
    let (tx_data_length, tx_data_digest) = blocks
        .iter()
        .flat_map(|b| b.body().transactions.iter())
        .tx_bytes_hash_in(rlp_buffer.as_mut());

    let block_ctxs = blocks.iter().map(BlockContextV2::from).collect();

    let prev_msg_queue_hash = witness.prev_msg_queue_hash.into();
    let sbv_chunk_info = {
        let mut builder = ChunkInfoBuilder::new(&chain_spec, blocks);
        builder.prev_msg_queue_hash(prev_msg_queue_hash);
        builder
            .build(withdraw_root)
            .into_euclid_v2()
            .expect("euclid-v2")
    };
    let post_msg_queue_hash = sbv_chunk_info.post_msg_queue_hash;

    assert_eq!(
        sbv_chunk_info.post_state_root, post_state_root,
        "state root mismatch"
    );

    openvm::io::println(format!("withdraw_root = {:?}", withdraw_root));
    openvm::io::println(format!("tx_bytes_hash = {:?}", tx_data_digest));

    ChunkInfo {
        chain_id: sbv_chunk_info.chain_id,
        prev_state_root: sbv_chunk_info.prev_state_root,
        post_state_root: sbv_chunk_info.post_state_root,
        withdraw_root,
        tx_data_digest,
        prev_msg_queue_hash,
        post_msg_queue_hash,
        tx_data_length: u64::try_from(tx_data_length).expect("tx_data_length: u64"),
        initial_block_number,
        block_ctxs,
    }
}
