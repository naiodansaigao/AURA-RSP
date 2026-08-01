#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/common.sh"

# The public paper artifact excludes the large upstream unit-test fixture tree.
# The pinned upstream provenance remains in UPSTREAM.md; this acceptance script
# exercises both network modes and every AURA security/lifecycle self-test.
"$ROOT/integration-scripts/run_standard_demo.sh" |
    tee "$RESULT_DIR/standard-integration-test.txt"
"$ROOT/integration-scripts/test_aura_integration.sh" |
    tee "$RESULT_DIR/aura-network-integration-test.txt"
"$PYTHON" -m pySim.esim.aura.selftest |
    tee "$RESULT_DIR/aura-security-selftest.txt"
"$ROOT/integration-scripts/run_lifecycle_demo.sh" |
    tee "$RESULT_DIR/aura-lifecycle-network-test.txt"
"$ROOT/integration-scripts/run_lifecycle_selftest.sh" |
    tee "$RESULT_DIR/aura-lifecycle-selftest-suite.txt"
"$ROOT/integration-scripts/run_lifecycle_restart_recovery.sh" |
    tee "$RESULT_DIR/aura-lifecycle-restart-recovery.txt"

grep -q STANDARD_PYSIM_INTEGRATION_ALL_PASS \
    "$RESULT_DIR/standard-integration-test.txt"
grep -q AURA_INTEGRATION_REGRESSION_PASS \
    "$RESULT_DIR/aura-network-integration-test.txt"
grep -q AURA_INTEGRATED_SECURITY_SELFTEST_PASS \
    "$RESULT_DIR/aura-security-selftest.txt"
grep -q AURA_INTEGRATED_LIFECYCLE_DEMO_PASS \
    "$RESULT_DIR/aura-lifecycle-network-test.txt"
grep -q AURA_INTEGRATED_LIFECYCLE_SELFTEST_PASS \
    "$RESULT_DIR/aura-lifecycle-selftest-suite.txt"
grep -q AURA_INTEGRATED_LIFECYCLE_RESTART_RECOVERY_PASS \
    "$RESULT_DIR/aura-lifecycle-restart-recovery.txt"

echo "PYSIM_AURA_ALL_TESTS_PASS"
