#!/usr/bin/env bash
#
# Runs the test suite under Valgrind's Memcheck.
#
#   scripts/valgrind-test.sh                 # whole suite
#   scripts/valgrind-test.sh --test memcheck # just the crabgrind-driven tests
#   scripts/valgrind-test.sh --release       # faster, less precise line numbers
#
# Any arguments are passed through to `cargo test`. Everything after `--` goes
# to the test harness, e.g.:
#
#   scripts/valgrind-test.sh -- --nocapture matching_rule
#
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

command -v valgrind >/dev/null || {
	echo "valgrind not found; install it (apt install valgrind) and retry" >&2
	exit 127
}

# Point cargo's test runner at the Valgrind wrapper for this host triple.
triple=$(rustc -vV | awk '/^host:/ { print $2 }')
runner_var="CARGO_TARGET_$(printf '%s' "$triple" | tr '[:lower:]-' '[:upper:]_')_RUNNER"
export "$runner_var=$root/scripts/valgrind-runner.sh"

# Memcheck's leak counters are process-wide, so the measuring tests must not
# run concurrently with anything else that allocates.
export RUST_TEST_THREADS=1

# Turns the memcheck tests' "not under Valgrind" skip into a failure, so this
# entry point cannot pass vacuously.
export MODSEC_REQUIRE_VALGRIND=1

echo "running the suite under $(valgrind --version) via $runner_var" >&2
exec cargo test --features valgrind "$@"
