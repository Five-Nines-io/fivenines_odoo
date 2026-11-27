#!/usr/bin/env bash
# Check that the release zip installs AND upgrades on one Odoo serie.
#
#   tools/check_release_zip.sh <zip> <database> <odoo command...>
#
# The odoo command is everything that runs odoo-bin with its database options,
# without -d nor --addons-path, for example (from source):
#   tools/check_release_zip.sh dist/fivenines_monitoring.zip fn_zip_17 \
#       ~/odoo-src/venv-17.0/bin/python ~/odoo-src/odoo-17.0/odoo-bin \
#       --db_host=localhost --db_user=$USER --addons-path-prefix=~/odoo-src/odoo-17.0/addons
# or (the official image; the extraction directory is mounted at the same path):
#   tools/check_release_zip.sh dist/fivenines_monitoring.zip fn_zip_17 \
#       docker run --rm --network host -e HOST=127.0.0.1 -e USER=odoo -e PASSWORD=odoo \
#       -v "$TMPDIR:$TMPDIR" odoo:17.0 --
# `--addons-path-prefix=<dirs>` (consumed here) is put in front of the module
# directory in --addons-path. The database must not exist yet.
#
# Steps: unpack the zip; install the module (-i); bump the unpacked version
# x.y to x.(y+1) and add a post-migration script in migrations/x.(y+1)/;
# upgrade (-u). The upgrade
# must run that migration, which proves the serie accepts the serie-free version
# and compares it with the installed one.
set -euo pipefail
zip=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
db=$2
shift 2
prefix=
args=()
for a in "$@"; do
    case "$a" in
        --addons-path-prefix=*) prefix="${a#--addons-path-prefix=}," ;;
        *) args+=("$a") ;;
    esac
done
base=${TMPDIR:-/tmp}
work=$(mktemp -d "$base/fn-zip.XXXXXX")
chmod 755 "$work"
trap 'rm -rf "$work"' EXIT
python3 -m zipfile -e "$zip" "$work"
chmod -R a+rX "$work"
test -f "$work/fivenines_monitoring/__manifest__.py"
addons="--addons-path=${prefix}${work}"

echo "== install from $(basename "$zip") into $db"
"${args[@]}" -d "$db" -i fivenines_monitoring "$addons" --stop-after-init --log-level=warn \
    --http-port=8599 2>&1 | tail -20

manifest="$work/fivenines_monitoring/__manifest__.py"
old=$(python3 -c "import ast, sys; print(ast.literal_eval(open(sys.argv[1]).read())['version'])" "$manifest")
new=$(python3 -c "import sys; p = sys.argv[1].split('.'); p[-1] = str(int(p[-1]) + 1); print('.'.join(p))" "$old")
sed -i "s/'version': '$old'/'version': '$new'/" "$manifest"
grep -q "'version': '$new'" "$manifest"
mkdir -p "$work/fivenines_monitoring/migrations/$new"
cat > "$work/fivenines_monitoring/migrations/$new/post-migrate.py" <<'PY'
import logging

from odoo import release


def migrate(cr, version):
    logging.getLogger('odoo.addons.fivenines_monitoring').warning(
        'FIVENINES_UPGRADE_OK serie=%s from=%s', release.serie, version)
PY
chmod -R a+rX "$work"

echo "== upgrade $old -> $new"
log=$("${args[@]}" -d "$db" -u fivenines_monitoring "$addons" --stop-after-init --log-level=warn \
    --http-port=8599 2>&1) || { printf '%s\n' "$log" | tail -40; exit 1; }
printf '%s\n' "$log" | grep FIVENINES_UPGRADE_OK || {
    printf '%s\n' "$log" | tail -40
    echo "the upgrade did not run the $new migration" >&2
    exit 1
}
if printf '%s\n' "$log" | grep -E " (ERROR|CRITICAL) $db "; then
    echo "errors logged during the upgrade" >&2
    exit 1
fi
echo "OK: $(basename "$zip") installs and upgrades ($old -> $new)"
