#!/usr/bin/env bash
PYTHON=/usr/local/bin/python3.13
brew install gcc openblas cmake pkg-config               # deps
OPENBLAS=$(brew --prefix openblas)
export LDFLAGS="-L${OPENBLAS}/lib"
export CPPFLAGS="-I${OPENBLAS}/include"
export PKG_CONFIG_PATH="${OPENBLAS}/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export CFLAGS="$CPPFLAGS"
export FFLAGS="$CPPFLAGS"

TMP=$(mktemp -d)
pushd "$TMP"
$PYTHON -m pip download --no-binary=:all: --no-deps d3graph
SDIST=$(ls d3graph-* | grep -E '\.(tar\.gz|zip)$' | head -n1)
case "$SDIST" in
  *.tar.gz) tar -xzf "$SDIST" ;;
  *.zip)    unzip -q "$SDIST" ;;
esac
PKG_DIR=$(find . -maxdepth 1 -type d -name 'd3graph-*' | head -n1)
cd "$PKG_DIR"
sed -i '' -e 's/\bsklearn\b/scikit-learn/g' requirements.txt || true
$PYTHON -m pip install .
popd
rm -rf "$TMP"

: <<'ORIGINAL'
#!/usr/bin/env bash
PYTHON=/usr/local/bin/python3.13
TMP=$(mktemp -d)
pushd "$TMP"
$PYTHON -m pip download --no-binary=:all: d3graph
SDIST=$(ls d3graph-*.tar.gz)
tar -xzf "$SDIST"
PKG_DIR=${SDIST%.tar.gz}
cd "$PKG_DIR"
sed -i '' -e 's/\bsklearn\b/scikit-learn/g' requirements.txt
$PYTHON -m pip install .
popd
rm -rf "$TMP"
ORIGINAL