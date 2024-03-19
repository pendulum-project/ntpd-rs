#!/usr/bin/env bash

set -eo pipefail

: "${RELEASE_TARGETS:=aarch64-unknown-linux-gnu,armv7-unknown-linux-gnueabihf,x86_64-unknown-linux-gnu,i686-unknown-linux-gnu}"
IFS=',' read -r -a targets <<< "$RELEASE_TARGETS"

target_dir="target/pkg"

rm -rf "$target_dir"
mkdir -p "$target_dir"

package_version=$(cargo read-manifest --manifest-path ntpd/Cargo.toml | jq -r .version)
toolchain=$(rustup show active-toolchain | cut -d' ' -f1)
host_target=$(echo "$toolchain" | cut -d'-' -f2-)
sysroot=$(rustc --print sysroot)
llvm_tools_path="$sysroot/lib/rustlib/$host_target/bin"

echo "--- Running on toolchain '${toolchain}', make sure the llvm-tools component is installed"
echo "--- Host target is '$host_target'"

for target in "${targets[@]}"; do
    dbg_sym_tar="ntpd-rs_dbg_$package_version-$target.tar.gz"

    echo "--- Calling cross for building ntpd package for target '$target'"
    cross build --target "$target" --package ntpd --release --features "${RELEASE_FEATURES:-}"

    echo "--- Creating separate debug symbol files for target '$target'"
    (
        cd "target/$target/release"
        find . -maxdepth 1 -type f -executable -print0 | while IFS= read -r -d '' file; do
            echo "--- Writing debug symbols from '$file' to '$file.dbg'"
            "$llvm_tools_path/llvm-strip" --only-keep-debug -o "$file.dbg" "$file"
            chmod -x "$file.dbg"
            echo "--- Removing all symbols from binary '$file'"
            "$llvm_tools_path/llvm-strip" -s "$file"
        done
    );

    echo "--- Create tar for debug symbols"
    (
        cd "target/$target/release"
        rm -f "$dbg_sym_tar"
        find . -maxdepth 1 -type f -name '*.dbg' -exec tar uvf "$dbg_sym_tar" {} +
    );

    echo "--- Creating deb package"
    cargo deb --no-build --no-strip --target "$target" --compress-type xz --package ntpd

    echo "--- Creating rpm package"
    cargo generate-rpm --payload-compress xz --package ntpd --target "$target" --target-dir target

    echo "--- Copying output files to target"
    cp "target/$target/release/$dbg_sym_tar" "$target_dir/"
    find "target/$target/debian" -maxdepth 1 -type f -name '*.deb' -exec cp "{}" "$target_dir/" \;
    find "target/$target/generate-rpm" -maxdepth 1 -type f -name '*.rpm' -exec cp "{}" "$target_dir/" \;
done

echo "--- Generating SHA256SUMS file"
(
    cd $target_dir
    sha256sum -b * > SHA256SUMS
)

echo "--- Done, output is in $target_dir"


