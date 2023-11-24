#!/usr/bin/env bash

set -eo pipefail

print_help() {
    echo "Usage: utils/prepare-artifacts.sh OPTIONS"
    echo ""
    echo "Options:"
    echo " --[no-]reset                 Clear the pkg directory or not (default: no)"
    echo " --[no-]delete-zips           Delete the downloaded zip files or not (default: no)"
    echo " --[no-]download-artifacts    Download the artifacts or not (default: no)"
    echo " --api-token TOKEN            The Github API token for downloading artifacts"
    echo " --run-id ID                  The id of the Workflow run for which to download artifacts"
}

GITHUB_API_TOKEN=
RUN_ID=
TARGET_DIR="target/pkg"
DO_RESET=false
DELETE_ZIPS=false
DOWNLOAD_ARTIFACTS=false
ZIP_DOWNLOADS_FOLDER="$TARGET_DIR/zips"


while [[ $# -gt 0 ]]; do
    case $1 in
        --reset)
            DO_RESET=true
        ;;
        --no-reset)
            DO_RESET=false
        ;;
        --delete-zips)
            DELETE_ZIPS=true
        ;;
        --no-delete-zips)
            DELETE_ZIPS=false
        ;;
        --download-artifacts)
            DOWNLOAD_ARTIFACTS=true
        ;;
        --no-download-artifacts)
            DOWNLOAD_ARTIFACTS=false
        ;;
        --api-token)
            GITHUB_API_TOKEN="$2"
            shift
        ;;
        --run-id)
            RUN_ID="$2"
            shift
        ;;
        --help)
            print_help
            exit 0
        ;;
    esac
    shift
done

if [ "$DOWNLOAD_ARTIFACTS" = true ] && ([ -z "$GITHUB_API_TOKEN" ] || [ -z "$RUN_ID" ]); then
    if [ -z "$GITHUB_API_TOKEN" ]; then
        echo "ERROR: Missing Github API token"
    fi

    if [ -z "$RUN_ID" ]; then
        echo "ERROR: Missing github workflow run id"
    fi
    print_help
    exit 1
fi

if [ "$DO_RESET" = true ]; then
    echo "Resetting target dir"
    rm -rf "$TARGET_DIR"
fi

mkdir -p "$ZIP_DOWNLOADS_FOLDER"

if [ "$DOWNLOAD_ARTIFACTS" = true ]; then
    echo "Retrieving artifacts from run"
    artifacts_json=$(curl -L \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -H "Authorization: Bearer $GITHUB_API_TOKEN" \
        https://api.github.com/repos/pendulum-project/ntpd-rs/actions/runs/$RUN_ID/artifacts)

    echo "Extracting artifact urls"
    artifact_urls=$(echo "$artifacts_json" | jq -r '.artifacts[] | (.name + ";" + .archive_download_url)')

    echo "Download artifacts"
    while read artifact; do
        IFS=';' read -r name url <<< "$artifact"
        echo "Downloading artifact '$name' from '$url'"
        zipfile="$ZIP_DOWNLOADS_FOLDER/$name.zip"
        curl -L \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            -H "Authorization: Bearer $GITHUB_API_TOKEN" \
            -o "$zipfile" "$url"
    done < <(echo "$artifact_urls")
    echo "Downloads complete"
fi

for f in $(find "$ZIP_DOWNLOADS_FOLDER" -type f); do
    echo "Extracting downloaded zip file '$f'"
    unzip -d "$TARGET_DIR" "$f"
done

if [ "$DELETE_ZIPS" = true ]; then
    echo "Delete the downloaded zips"
    rm -rf "$ZIP_DOWNLOADS_FOLDER"
else
    echo "Not deleting any downloaded zips"
fi

echo "Flatten file structure"
find "$TARGET_DIR" -mindepth 2 -type f -not -path "$ZIP_DOWNLOADS_FOLDER/*" -exec mv -t "$TARGET_DIR" -i '{}' +

echo "Remove any leftover directories"
find "$TARGET_DIR" -mindepth 1 -type d -not -path "$ZIP_DOWNLOADS_FOLDER" -exec rm -Rf '{}' +

echo "Replace tildes by dashes for github"
for f in $(find "$TARGET_DIR" -type f); do
    newf=$(echo "$f" | sed 's/~/-/g')
    if [ "$f" != "$newf" ]; then
        mv "$f" "$newf"
    fi
done

echo "Create SHA256SUMS"
(cd "$TARGET_DIR" && rm -rf "SHA256SUMS" && find * -type f -not -name "SHA256SUMS" -exec sha256sum -b {} + | tee "SHA256SUMS")
