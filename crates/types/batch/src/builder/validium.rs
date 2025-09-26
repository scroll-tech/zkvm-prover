use types_base::public_inputs::{batch::BatchInfo, chunk::ChunkInfo};

use crate::header::{BatchHeader, ValidiumBatchHeader, validium::BatchHeaderValidium};

pub struct ValidiumBuilderArgs {
    pub header: BatchHeaderValidium,
    pub chunk_infos: Vec<ChunkInfo>,
    #[allow(dead_code)]
    pub batch_bytes: Vec<u8>,
}

impl ValidiumBuilderArgs {
    pub fn new(
        header: BatchHeaderValidium,
        chunk_infos: Vec<ChunkInfo>,
        batch_bytes: Vec<u8>,
    ) -> Self {
        Self {
            header,
            chunk_infos,
            batch_bytes,
        }
    }
}

pub struct ValidiumBatchInfoBuilder;

impl ValidiumBatchInfoBuilder {
    pub fn build(args: ValidiumBuilderArgs) -> BatchInfo {
        match &args.header {
            BatchHeaderValidium::V1(_) => {
                // nothing to do for v1 header since blob data is not included in validium
            }
        }

        let (first_chunk, last_chunk) = (
            args.chunk_infos
                .first()
                .expect("at least one chunk in batch"),
            args.chunk_infos
                .last()
                .expect("at least one chunk in batch"),
        );

        // Additionally check that the batch's commitment field is set correctly.
        assert_eq!(last_chunk.post_blockhash.to_vec(), args.header.commitment());

        BatchInfo {
            parent_state_root: first_chunk.prev_state_root,
            parent_batch_hash: args.header.parent_batch_hash(),
            state_root: last_chunk.post_state_root,
            batch_hash: args.header.batch_hash(),
            chain_id: last_chunk.chain_id,
            withdraw_root: last_chunk.withdraw_root,
            prev_msg_queue_hash: first_chunk.prev_msg_queue_hash,
            post_msg_queue_hash: last_chunk.post_msg_queue_hash,
            encryption_key: first_chunk.encryption_key.clone(),
        }
    }
}
