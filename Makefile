.PHONY: build release test clippy wasm validate-plugins ui-install ui-test ui-build check-all clean

build:
	cargo build -p morph-core

release:
	cargo build --release -p morph-core

test:
	cargo test -p morph-core -- --nocapture

clippy:
	cargo clippy -p morph-core --all-targets -- -D warnings

wasm:
	node scripts/compile-wasm.mjs

validate-plugins:
	node scripts/validate-plugins.mjs

ui-install:
	cd ui && npm install

ui-test:
	cd ui && npm run typecheck && npm test

ui-build:
	cd ui && npm run build

check-all: wasm validate-plugins clippy test ui-test ui-build

clean:
	cargo clean
	rm -rf dist ui/dist
