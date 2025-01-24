use super::ProvingTask;

#[derive(Debug, Clone)]
pub struct BundleProvingTask;

impl ProvingTask for BundleProvingTask {
    fn identifier(&self) -> String {
        unimplemented!()
    }
}
