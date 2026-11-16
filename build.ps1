$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
 New-Item -ItemType Directory -Force -Path bin | Out-Null
 go build -mod=readonly -trimpath -o bin/keryxbridge.exe ./cmd/keryxbridge
 if ($LASTEXITCODE -ne 0) { throw 'Go build failed' }
 cargo build --locked --release --manifest-path verifier/Cargo.toml
 if ($LASTEXITCODE -ne 0) { throw 'Rust build failed' }
 Copy-Item -LiteralPath verifier/target/release/keryx-bridge-verifier.exe -Destination bin/keryx-bridge-verifier.exe
 $lines = foreach ($name in @('keryxbridge.exe','keryx-bridge-verifier.exe')) {
  '{0}  {1}' -f (Get-FileHash -LiteralPath (Join-Path 'bin' $name) -Algorithm SHA256).Hash.ToLowerInvariant(),$name
 }
 [System.IO.File]::WriteAllLines((Join-Path $PSScriptRoot 'bin/SHA256SUMS'), $lines)
} finally { Pop-Location }
