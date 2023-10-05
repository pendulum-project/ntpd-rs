#!/usr/bin/env bash

set -eo pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: utils/download-artifacts.sh [api-token] [run-id]"
    exit 1
fi

GITHUB_API_TOKEN="$1"
RUN_ID="$2"
TARGET_DIR="target/pkg"

echo "Resetting target dir"
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"

echo "Retrieving artifacts from run"
artifacts_json=$(curl -L \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "Authorization: Bearer $GITHUB_API_TOKEN" \
    https://api.github.com/repos/pendulum-project/ntpd-rs/actions/runs/$RUN_ID/artifacts)

echo "Extracting artifact urls"
artifact_urls=$(echo "$artifacts_json" | jq -r '.artifacts[] | (.name + ";" + .archive_download_url)')

echo "Download and extract artifacts"
while read artifact; do
    IFS=';' read -r name url <<< "$artifact"
    echo "Downloading artifact '$name' from '$url'"
    zipfile="$TARGET_DIR/$name.zip"
    curl -L \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -H "Authorization: Bearer $GITHUB_API_TOKEN" \
        -o "$zipfile" "$url"
    echo "Extracting downloaded zip file"
    unzip -d "$TARGET_DIR" "$zipfile"
    echo "Removing zip file"
    rm "$zipfile"
done < <(echo "$artifact_urls")

echo "Flatten file structure"
find "$TARGET_DIR" -mindepth 2 -type f -exec mv -t "$TARGET_DIR" -i '{}' +

echo "Remove old directories"
rm -R -- "$TARGET_DIR/"*/

echo "Fixing tilde character for github"
for f in $(find "$TARGET_DIR" -type f); do
    newf=$(echo "$f" | sed 's/~/-/g')
    if [ "$f" != "$newf" ]; then
        mv "$f" "$newf"
    fi

done

echo "Create SHA256SUMS"
(cd "$TARGET_DIR" && sha256sum -b * > "SHA256SUMS")
