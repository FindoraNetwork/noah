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

bench:
	cargo bench --workspace

fmt:
	cargo fmt --all
