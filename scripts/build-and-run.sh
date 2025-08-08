set -euxo pipefail
bash build-guest-actions-entrypoint.sh 2>&1 | tee build.log
make test-e2e-bundle 2>&1 | tee e2e.log
