FROM rust:1.93

WORKDIR /app

# Host toolchain required by rust-toolchain.toml (openvm-sdk "tco" feature).
RUN rustup toolchain install nightly-2026-01-18 && \
    rustup component add --toolchain nightly-2026-01-18 llvm-tools rustc-dev

# cargo-openvm CLI from the pinned OpenVM rev, plus the RV64 guest toolchain
# (installs the `openvm-1.94.1` rustup toolchain used by openvm-build).
RUN cargo install --locked --git https://github.com/openvm-org/openvm.git --rev fc1a0001e63d5685fb40c1ffb10c6ce0d55677ce cargo-openvm && \
    cargo openvm toolchain install && \
    ln -s "$(rustup which cargo)" "$(dirname "$(rustup +openvm-1.94.1 which rustc)")/cargo"

ENV OPENVM_RUST_TOOLCHAIN=openvm-1.94.1

RUN wget https://github.com/ethereum/solc-bin/raw/refs/heads/gh-pages/linux-amd64/solc-linux-amd64-v0.8.19+commit.7dd6d404 -O /usr/local/bin/solc && \
    chmod +x /usr/local/bin/solc

COPY . .

