#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."
exec go test -tags integration ./integration/mit -run '^TestGenerateFixtures$' -count=1 -v
