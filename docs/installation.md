# Installation

## From Source

Requires Go 1.26 or later.

```bash
git clone https://github.com/asymmetric-effort/leakdetector.git
cd leakdetector
make build
```

Binaries are output to `./build/<os>/<arch>/leakdetector`.

## Supported Platforms

| OS      | Architecture |
|---------|-------------|
| Linux   | amd64       |
| Linux   | arm64       |
| macOS   | amd64       |
| macOS   | arm64       |
| Windows | amd64       |
| Windows | arm64       |

## From Release Binaries

Download the latest release from the
[GitHub Releases](https://github.com/asymmetric-effort/leakdetector/releases)
page. Extract the binary and place it in your `$PATH`.

```bash
# Linux amd64 example
tar -xzf leakdetector_linux_amd64.tar.gz
sudo mv leakdetector /usr/local/bin/
```

## Verify Installation

```bash
leakdetector --version
```
