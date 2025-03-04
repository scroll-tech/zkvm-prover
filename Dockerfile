FROM rust:1.85

Run rustup target add aarch64-unknown-linux-gnu
RUN rustup toolchain install nightly-2024-12-06-aarch64-unknown-linux-gnu

WORKDIR /app

COPY . .

CMD [ "sh", "build-guest.sh" ]
