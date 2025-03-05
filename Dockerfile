FROM rust:1.85

RUN rustup toolchain install nightly-2024-12-06-x86_64-unknown-linux-gnu
RUN rustup toolchain install nightly-2024-10-30-x86_64-unknown-linux-gnu
RUN rustup component add rust-src --toolchain nightly-2024-10-30-x86_64-unknown-linux-gnu

WORKDIR /github/workspace

COPY . .

ENTRYPOINT ["/github/workspace/build-guest-actions-entrypoint.sh"]
