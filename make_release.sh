#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p bin
go build -mod=readonly -trimpath -o bin/keryxbridge ./cmd/keryxbridge
cargo build --release --locked --manifest-path verifier/Cargo.toml
cp verifier/target/release/keryx-bridge-verifier bin/keryx-bridge-verifier
(cd bin && sha256sum keryxbridge keryx-bridge-verifier > SHA256SUMS)
