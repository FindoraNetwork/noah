FROM nexus.findora.org/bulletproofs:batch_verification AS BP
FROM rustlang/rust:nightly as builder
RUN cargo install cargo-audit
RUN mkdir /app
WORKDIR /app/
COPY --from=BP /app /src/bulletproofs
COPY ./Cargo* /app/
COPY ./rustfmt.toml /app/
COPY ./algebra /app/algebra
COPY ./crypto /app/crypto
COPY ./utils /app/utils
COPY ./utilities /app/utilities
COPY ./zei_api /app/zei_api
RUN cargo audit
RUN cargo test --workspace
RUN rm -rf /app/target
FROM debian:buster
COPY --from=builder /app /app
COPY --from=BP /app /src/bulletproofs
