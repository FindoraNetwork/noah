 #!/usr/bin/env bash

# "strict mode" -- see
# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

# move to the root of the git repository we're in
GIT_ROOT="$(git rev-parse --show-toplevel)"
pushd $GIT_ROOT >/dev/null

# Find all git references in Cargo.toml files and change them to path based for dockers
find . -iname Cargo.toml -print0 | xargs -0 sed -i 's?bulletproofs = .*?bulletproofs = { path = "/src/bulletproofs", features = ["yoloproofs"] }?g'
#If you need to reset this
#find . -iname Cargo.toml -print0 | xargs -0 git checkout

# return to original working directory
popd >/dev/null
