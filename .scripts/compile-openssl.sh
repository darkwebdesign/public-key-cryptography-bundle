#!/usr/bin/env bash

readonly DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)";
readonly SCRIPT="$(basename "${BASH_SOURCE[0]}")";

readonly VERSION="${1}";
readonly VERSION_PREFIX="$(echo "$VERSION" | sed --regexp-extended 's/^([0-9]+\.[0-9]+\.[0-9]+).*$/\1/')";

readonly ROOT_DIRECTORY="$(dirname "$DIR")";
readonly TEMP_DIRECTORY="$(mktemp --directory)";
readonly OUTPUT_DIRECTORY="$ROOT_DIRECTORY/build/openssl/$VERSION";

if [[ -z "$VERSION" ]]; then
    echo "$SCRIPT: no version specified!";
    exit 1;
fi;

echo "VERSION: $VERSION";
echo "TEMP_DIRECTORY: $TEMP_DIRECTORY";
echo "OUTPUT_DIRECTORY: $OUTPUT_DIRECTORY";

read -p 'Press enter to continue...';

wget --timestamping --directory-prefix "$TEMP_DIRECTORY/" "https://www.openssl.org/source/openssl-$VERSION.tar.gz";

if [[ $? -ne 0 ]]; then
    wget --timestamping --directory-prefix "$TEMP_DIRECTORY/" "https://www.openssl.org/source/old/$VERSION_PREFIX/openssl-$VERSION.tar.gz";
    
    if [[ $? -ne 0 ]]; then
        echo "$SCRIPT: version not found!";
        exit 1;
    fi;
fi;

tar --extract --verbose --gzip --directory "$TEMP_DIRECTORY/" --file "$TEMP_DIRECTORY/openssl-$VERSION.tar.gz";

cd "$TEMP_DIRECTORY/openssl-$VERSION";

mkdir --parents "$OUTPUT_DIRECTORY";

./config --prefix="$OUTPUT_DIRECTORY" --openssldir="$OUTPUT_DIRECTORY";

make;
make test;
make install;

rm -rf "$TEMP_DIRECTORY";
