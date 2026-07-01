/// SP1 crypto provider placeholder.
///
/// For the PoC we rely on revm's default pure-Rust crypto implementations
/// (sha2, k256, substrate-bn, etc.) which run inside the SP1 zkVM without
/// additional patches. This is functionally correct but slower than a
/// precompile-accelerated backend.
#[derive(Debug)]
pub struct Crypto;

impl Crypto {
    /// No-op install: revm will fall back to its built-in DefaultCrypto.
    pub fn install() {
        // TODO: implement SP1 precompile-accelerated crypto backend for
        // production performance.
    }
}
