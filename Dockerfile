FROM 563536162678.dkr.ecr.us-west-2.amazonaws.com/bulletproofs:batch_verification AS BP
FROM 563536162678.dkr.ecr.us-west-2.amazonaws.com/rust:2020-09-15 as builder
RUN cargo install cargo-audit
RUN mkdir /app
WORKDIR /app/
COPY --from=BP /app /src/bulletproofs
COPY ./Cargo* /app/
COPY ./rustfmt.toml /app/
COPY ./algebra /app/algebra
COPY ./crypto /app/crypto
COPY ./poly-iops /app/poly-iops
COPY ./utils /app/utils
COPY ./bench-utils /app/bench-utils
COPY ./zei_api /app/zei_api
RUN cargo audit
RUN cargo test --workspace --release
RUN rm -rf /app/target
FROM debian:buster
COPY --from=builder /app /app
COPY --from=BP /app /src/bulletproofs
