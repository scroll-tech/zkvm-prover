FROM rust:1.85

WORKDIR /app

COPY . .

CMD [ "sh", "build-guest.sh" ]
