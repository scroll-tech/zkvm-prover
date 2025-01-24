use super::ProvingTask;

#[derive(Debug, Clone)]
pub struct BundleProvingTask;

impl ProvingTask for BundleProvingTask {
    fn identifier(&self) -> String {
        unimplemented!()
    }

    fn to_witness_serialized(&self) -> Result<rkyv::util::AlignedVec, rkyv::rancor::Error> {
        unimplemented!()
    }
}
