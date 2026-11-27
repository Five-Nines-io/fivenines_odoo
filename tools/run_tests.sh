#!/bin/sh
# Part of Fivenines Monitoring. License LGPL-3.
# Run the module's tests on Odoo versions checked out from source, in parallel.
#
#   tools/run_tests.sh [16.0 17.0 18.0 19.0]
#
# ODOO_SRC holds odoo-<version>/ (an odoo/odoo checkout) and venv-<version>/
# (a virtualenv with its requirements). DB_HOST / DB_USER reach a PostgreSQL
# server where DB_USER may create databases. Each version uses a throwaway
# database (fn_test_<major>) that is dropped afterwards.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
ODOO_SRC=${ODOO_SRC:-$HOME/odoo-src}
DB_HOST=${DB_HOST:-localhost}
DB_USER=${DB_USER:-${USER:-$(id -un)}}
LOGDIR=${LOGDIR:-$(mktemp -d)}
mkdir -p "$LOGDIR"
# Arguments that are not Odoo versions (e.g. test file paths a gate passes)
# are ignored: Odoo runs the whole module's suite.
versions=""
for a in "$@"; do
    case "$a" in [0-9]*.0) versions="$versions $a" ;; esac
done
# shellcheck disable=SC2086
set -- ${versions:-16.0 17.0 18.0 19.0}

run_one() {
    v=$1; major=${v%%.*}; db=fn_test_$major; log=$LOGDIR/odoo-$v.log
    dropdb -h "$DB_HOST" -U "$DB_USER" --if-exists "$db" 2>/dev/null
    "$ODOO_SRC/venv-$v/bin/python" "$ODOO_SRC/odoo-$v/odoo-bin" -d "$db" \
        --addons-path="$ODOO_SRC/odoo-$v/addons,$REPO" \
        --db_host="$DB_HOST" --db_user="$DB_USER" \
        -i fivenines_monitoring --test-tags=/fivenines_monitoring \
        --stop-after-init --http-port=$((18000 + major)) --log-level=info > "$log" 2>&1
    rc=$?
    dropdb -h "$DB_HOST" -U "$DB_USER" --if-exists "$db" 2>/dev/null
    line=$(grep -E "odoo.tests.result: [0-9]+ failed, [0-9]+ error\(s\) of [0-9]+ tests" "$log" | tail -1 | sed 's/.*odoo.tests.result: //')
    # same gate as CI: no failure, at least one test ran, and no ERROR/CRITICAL
    # line logged for the test database outside the test results
    logged=$(grep -cE " (ERROR|CRITICAL) $db " "$log")
    if [ $rc -eq 0 ] && echo "$line" | grep -qE "^0 failed, 0 error\(s\) of [1-9][0-9]* tests" && [ "$logged" -eq 0 ]; then
        echo "Odoo $v: PASS ($line)"
    else
        echo "Odoo $v: FAIL rc=$rc (${line:-no result line}; $logged ERROR/CRITICAL line(s)) log=$log"
        grep -E "(ERROR|FAIL): " "$log" | head -20
        return 1
    fi
}

pids=""
for v in "$@"; do
    run_one "$v" > "$LOGDIR/summary-$v.txt" 2>&1 &
    pids="$pids $!"
done
fail=0
for p in $pids; do wait "$p" || fail=1; done
cat "$LOGDIR"/summary-*.txt
total=$(cat "$LOGDIR"/summary-*.txt | grep -oE "of [0-9]+ tests" | awk '{s+=$2} END {print s+0}')
echo "TOTAL: $total tests across $# version(s), failed=$fail, logs=$LOGDIR"
exit $fail
