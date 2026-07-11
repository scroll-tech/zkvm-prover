FROM rust:1.93

WORKDIR /app

# Install the nightly toolchain used by openvm-build for guest programs,
# plus the RISC-V target and rust-src needed for -Z build-std.
RUN rustup toolchain install nightly-2025-11-20 && \
    rustup target add --toolchain nightly-2025-11-20 riscv32im-unknown-none-elf && \
    rustup component add --toolchain nightly-2025-11-20 rust-src llvm-tools rustc-dev

RUN wget https://github.com/ethereum/solc-bin/raw/refs/heads/gh-pages/linux-amd64/solc-linux-amd64-v0.8.19+commit.7dd6d404 -O /usr/local/bin/solc && \
    chmod +x /usr/local/bin/solc

COPY . .

