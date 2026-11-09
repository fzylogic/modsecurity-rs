#!/usr/bin/env bash
#
# Cargo test runner: executes one test binary under Valgrind's Memcheck.
#
# Cargo invokes this with the binary and its arguments whenever
# CARGO_TARGET_<TRIPLE>_RUNNER points here; see scripts/valgrind-test.sh.
# Run it directly to check a single binary:
#
#   scripts/valgrind-runner.sh target/debug/deps/integration-<hash> --test-threads=1
#
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

# A definite or indirect leak, an invalid access, a double free or a read of
# uninitialised memory exits 99, which fails the cargo test run. "Still
# reachable" is not an error: the engine is a deliberate process-wide singleton
# that is never freed (see src/modsecurity.rs).
exec valgrind \
	--tool=memcheck \
	--leak-check=full \
	--show-leak-kinds=definite,indirect \
	--errors-for-leak-kinds=definite,indirect \
	--error-exitcode=99 \
	--num-callers=20 \
	--fair-sched=yes \
	--suppressions="$root/valgrind.supp" \
	${VALGRIND_EXTRA_ARGS:-} \
	"$@"
