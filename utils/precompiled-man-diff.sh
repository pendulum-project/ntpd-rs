#!/usr/bin/env bash

set -eo pipefail

rm -rf target/docs/man
utils/generate-man.sh target/docs/man

exec diff -r -s --color "docs/precompiled/man" "target/docs/man"
