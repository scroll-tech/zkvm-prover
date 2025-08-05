FROM rust:1.86

WORKDIR /app

COPY . .

ENTRYPOINT ["/app/build-guest-actions-entrypoint.sh"]
