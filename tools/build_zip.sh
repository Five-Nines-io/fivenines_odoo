#!/usr/bin/env bash
# Build the release zip of fivenines_monitoring: ONE zip for every Odoo serie
# (16.0 to 20.0), from the committed tree (git archive, so nothing untracked).
#
#   tools/build_zip.sh [<git ref>] [<out dir>]      (defaults: HEAD, dist/)
#
# Writes <out>/fivenines_monitoring.zip (the stable name behind the
# releases/latest/download/ link) and <out>/fivenines_monitoring-<version>.zip,
# plus SHA256SUMS. The zip holds one top-level directory, fivenines_monitoring/,
# to unpack into an addons directory.
set -euo pipefail
ref=${1:-HEAD}
out=${2:-dist}
root=$(git rev-parse --show-toplevel)
cd "$root"
manifest=$(git show "$ref:fivenines_monitoring/__manifest__.py")
version=$(printf '%s' "$manifest" | python3 -c "import ast, sys; print(ast.literal_eval(sys.stdin.read())['version'])")
# One tree for every serie: x.y, serie-free (see the comment in __manifest__.py:
# a serie prefix is refused by the other series, and Odoo 16 skips the
# migrations of a three-part x.y.z version).
if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+$'; then
    echo "manifest version must be x.y (two parts, no serie): $version" >&2
    exit 1
fi
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git archive --format=tar "$ref" fivenines_monitoring LICENSE | tar -x -C "$tmp"
mv "$tmp/LICENSE" "$tmp/fivenines_monitoring/LICENSE"
# deterministic: sorted entries, fixed timestamps, fixed permissions
python3 - "$tmp" <<'PY'
import os, sys, zipfile
root = sys.argv[1]
paths = []
for d, _dirs, files in os.walk(os.path.join(root, 'fivenines_monitoring')):
    paths += [os.path.join(d, f) for f in files]
with zipfile.ZipFile(os.path.join(root, 'module.zip'), 'w', zipfile.ZIP_DEFLATED) as z:
    for path in sorted(paths):
        info = zipfile.ZipInfo(os.path.relpath(path, root), (2000, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        with open(path, 'rb') as f:
            z.writestr(info, f.read())
PY
cp "$tmp/module.zip" "$out/fivenines_monitoring-$version.zip"
cp "$tmp/module.zip" "$out/fivenines_monitoring.zip"
(cd "$out" && sha256sum "fivenines_monitoring-$version.zip" "fivenines_monitoring.zip" > SHA256SUMS)
echo "version=$version"
echo "zip=$out/fivenines_monitoring-$version.zip"
