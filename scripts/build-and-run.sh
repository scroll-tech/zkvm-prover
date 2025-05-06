set -euxo pipefail
make build-guest 2>&1 | tee build.log
make test-e2e-bundle 2>&1 | tee e2e.log
