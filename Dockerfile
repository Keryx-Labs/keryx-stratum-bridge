FROM golang:1.26.11-bookworm AS go-builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY src ./src
RUN go build -mod=readonly -trimpath -o /out/keryxbridge ./cmd/keryxbridge

FROM rust:1.96.1-bookworm AS rust-builder
WORKDIR /build
COPY verifier ./verifier
RUN cargo build --release --locked --manifest-path verifier/Cargo.toml

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=go-builder /out/keryxbridge /bin/keryxbridge
COPY --from=rust-builder /build/verifier/target/release/keryx-bridge-verifier /bin/keryx-bridge-verifier
COPY cmd/keryxbridge/config.yaml /config.yaml
WORKDIR /
ENTRYPOINT ["/bin/keryxbridge", "-config", "/config.yaml"]
