all: lint

lint:
	cargo clippy --workspace
	cargo clippy --workspace --tests

build:
	cargo build

release:
	cargo build --release

test:
	cargo test --release --workspace
	cargo test --release --workspace -- --ignored

bench:
	cargo bench --workspace

fmt:
	cargo fmt
