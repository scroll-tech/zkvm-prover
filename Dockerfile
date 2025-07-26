FROM rust:1.86

#RUN rustup toolchain install nightly-2025-02-14-x86_64-unknown-linux-gnu
#RUN rustup component add rust-src --toolchain nightly-2025-02-14-x86_64-unknown-linux-gnu

WORKDIR /app

COPY . .

ENTRYPOINT ["/app/build-guest-actions-entrypoint.sh"]
