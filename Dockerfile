FROM rust:1.86

WORKDIR /app

RUN wget https://github.com/ethereum/solc-bin/raw/refs/heads/gh-pages/linux-amd64/solc-linux-amd64-v0.8.19+commit.7dd6d404 -O /usr/local/bin/solc && \
    chmod +x /usr/local/bin/solc

COPY . .

