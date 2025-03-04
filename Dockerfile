FROM rust:1.85 AS build

RUN rustup target add x86_64-unknown-linux-musl
RUN rustup toolchain install nightly-2024-12-06-x86_64-unknown-linux-musl --target x86_64-unknown-linux-musl

WORKDIR /app

COPY . .

CMD [ "sh", "build-guest.sh" ]
