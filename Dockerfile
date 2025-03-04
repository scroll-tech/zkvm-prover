FROM rust:1.85

RUN rustup toolchain install nightly-2024-12-06-x86_64-unknown-linux-gnu

WORKDIR /app

COPY . .

CMD [ "sh", "build-guest.sh" ]
