set -euxo pipefail
#make build-guest-local 2>&1 | tee build.log
make build-guest 2>&1 | tee build.log
#OUTPUT_PATH=`realpath .output/bundle-tests-20251113_053106/` GPU=1 make test-e2e-bundle 2>&1 | tee e2e.log
#GUEST_VERSION=0.5.2 
GPU=1 make test-e2e-bundle 2>&1 | tee e2e.log
