FROM rust:latest

WORKDIR /transfer

COPY . .

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive \
  apt-get install --no-install-recommends --assume-yes \
  protobuf-compiler
RUN cargo install --bin transfer-server --path .

EXPOSE 50051

CMD ["transfer-server"]
