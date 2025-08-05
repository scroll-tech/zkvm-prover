FROM rust:1.86

ORKDIR /app

COPY . .

ENTRYPOINT ["/app/build-guest-actions-entrypoint.sh"]
