#!/usr/bin/env bash

readonly DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)";
readonly SCRIPT="$(basename "${BASH_SOURCE[0]}")";

readonly VERSION="${1}";

readonly ROOT_DIRECTORY="$(dirname "$DIR")";
readonly BUILD_DIRECTORY="$ROOT_DIRECTORY/build/openssl/$VERSION";
readonly VENDOR_DIRECTORY="$ROOT_DIRECTORY/vendor";

if [[ -z "$VERSION" ]]; then
    echo "$SCRIPT: no version specified!";
    exit 1;
fi;

if [[ ! -d "$BUILD_DIRECTORY" ]]; then
    echo "$SCRIPT: version build not found!";
    exit 1;
fi;

export PATH="$BUILD_DIRECTORY/bin:$PATH";
export LD_LIBRARY_PATH="$BUILD_DIRECTORY/lib:$LD_LIBRARY_PATH";

cd "$ROOT_DIRECTORY";

"$VENDOR_DIRECTORY/bin/phpunit";
