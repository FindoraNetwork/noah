FROM nexus.findora.org/zcash-bn-fork:master as BN
FROM rustlang/rust:nightly
RUN cargo install cargo-audit
RUN mkdir /app
WORKDIR /app/
COPY --from=BN /app /src/zcash-bn-fork
COPY ./Cargo* /app/
COPY ./rustfmt.toml /app/
COPY ./tests /app/tests
COPY ./src /app/src
