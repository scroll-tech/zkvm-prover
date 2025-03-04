################################ STAGE 1 ################################

FROM alpine:3.20 AS build

LABEL org.opencontainers.image.source=https://github.com/rust-lang/docker-rust

RUN apk add --no-cache \
        ca-certificates \
        gcc \
	musl-dev \
	git \
	make

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=nightly-2024-12-06

RUN set -eux; \
    apkArch="$(apk --print-arch)"; \
    case "$apkArch" in \
        x86_64) rustArch='x86_64-unknown-linux-musl'; rustupSha256='55a7f503ce16250d1ffb227f0fa7aa8a9305924dca2890957c7fec7a4888111c' ;; \
        aarch64) rustArch='aarch64-unknown-linux-musl'; rustupSha256='415c9461158325e0d58af7f8fc61e85cd7f079e93f9784d266c5ee9c95ed762c' ;; \
        *) echo >&2 "unsupported architecture: $apkArch"; exit 1 ;; \
    esac; \
    url="https://static.rust-lang.org/rustup/archive/1.28.0/${rustArch}/rustup-init"; \
    wget "$url"; \
    echo "${rustupSha256} *rustup-init" | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --profile minimal --default-toolchain $RUST_VERSION --default-host ${rustArch}; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version;

RUN rustup toolchain install nightly-2024-10-30-aarch64-unknown-linux-musl

RUN rustup component add rust-src --toolchain nightly-2024-10-30-aarch64-unknown-linux-musl

################################ STAGE 2 ################################

FROM build

WORKDIR /app

COPY . .

ENTRYPOINT ["build-guest.sh"]
