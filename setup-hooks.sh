#!/usr/bin/env bash
set -e

GIT_ROOT="$(git rev-parse --show-toplevel)"
pushd ${GIT_ROOT}/.git/hooks/
for f in ../../hooks/*; do
  ln -s ${f} .
done
popd

