FROM nexus.findora.org/bulletproofs:batch_verification AS BP
FROM rustlang/rust:nightly as builder
RUN cargo install cargo-audit
RUN mkdir /app
WORKDIR /app/
COPY --from=BP /app /src/bulletproofs
COPY ./Cargo* /app/
COPY ./rustfmt.toml /app/
COPY ./tests /app/tests
COPY ./src /app/src
COPY ./algebra /app/algebra
COPY ./utilities /app/utilities
COPY ./benches /app/benches
RUN cargo audit
RUN cargo test
RUN rm -rf /app/target
FROM debian:buster
COPY --from=builder /app /app
COPY --from=BP /app /src/bulletproofs
