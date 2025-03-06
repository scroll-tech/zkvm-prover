use std::mem::ManuallyDrop;

use sbv::{
    core::{EvmDatabase, EvmExecutor},
    primitives::{
        BlockWitness, RecoveredBlock,
        chainspec::{
            BaseFeeParams, BaseFeeParamsKind, Chain,
            reth_chainspec::ChainSpec,
            scroll::{ScrollChainConfig, ScrollChainSpec},
        },
        ext::{BlockWitnessChunkExt, TxBytesHashExt},
        hardforks::SCROLL_DEV_HARDFORKS,
        types::{ChunkInfoBuilder, reth::Block},
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

    let pre_state_root = witnesses[0].pre_state_root();

    let chain = Chain::from_id(witnesses[0].chain_id());

    // enable all forks
    #[allow(unused_mut)]
    let mut hardforks = (*SCROLL_DEV_HARDFORKS).clone();
    // disable EuclidV2 if not configured
    {
        use sbv::primitives::{chainspec::ForkCondition, hardforks::ScrollHardfork};
        hardforks.insert(ScrollHardfork::EuclidV2, ForkCondition::Never);
    }

    let inner = ChainSpec {
        chain,
        genesis_hash: Default::default(),
        genesis: Default::default(),
        genesis_header: Default::default(),
        paris_block_and_final_difficulty: Default::default(),
        hardforks,
        deposit_contract: Default::default(),
        base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),
        prune_delete_limit: 20000,
        blob_params: Default::default(),
    };
    let config = ScrollChainConfig::mainnet();
    let chain_spec: ScrollChainSpec = ScrollChainSpec { inner, config };

    let (code_db, nodes_provider, block_hashes) = make_providers(witnesses);
    let nodes_provider = ManuallyDrop::new(nodes_provider);

    let mut db = ManuallyDrop::new(
        EvmDatabase::new_from_root(code_db, pre_state_root, &nodes_provider, block_hashes)
            .expect("failed to create EvmDatabase"),
    );
    for block in blocks.iter() {
        let output = ManuallyDrop::new(
            EvmExecutor::new(std::sync::Arc::new(chain_spec.clone()), &db, block)
                .execute()
                .expect("failed to execute block"),
        );
        db.update(&nodes_provider, output.state.state.iter())
            .expect("failed to update db");
    }

    let post_state_root = db.commit_changes();

    let withdraw_root = db.withdraw_root().expect("failed to get withdraw root");

    let sbv_chunk_info = {
        #[allow(unused_mut)]
        let mut builder = ChunkInfoBuilder::new(&chain_spec, pre_state_root, blocks);
        builder.build(withdraw_root)
    };

    assert_eq!(
        sbv_chunk_info.post_state_root(),
        post_state_root,
        "state root mismatch"
    );

    let mut rlp_buffer = ManuallyDrop::new(Vec::with_capacity(2048));
    let (_, tx_data_digest) = blocks
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
        data_hash: sbv_chunk_info
            .into_legacy()
            .expect("legacy chunk")
            .data_hash,
        tx_data_digest,
    }
}
