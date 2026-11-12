#!/bin/bash
# Build the C-API static library (include/maski.h) for iOS devices and Apple-silicon macOS and
# link a tiny C program against each, to prove the archive is complete.
# Output: target/<triple>/apple/libmaski.a
set -euo pipefail
cd "$(dirname "$0")/.."
export IPHONEOS_DEPLOYMENT_TARGET=15.0 MACOSX_DEPLOYMENT_TARGET=12.0
# Host proc-macro dylibs stripped by the `apple` profile fail to load on macOS 27 ("mis-aligned
# LINKEDIT string pool"); build scripts and proc macros keep their symbols.
export CARGO_PROFILE_APPLE_BUILD_OVERRIDE_STRIP=false
for t in aarch64-apple-ios aarch64-apple-darwin; do
  cargo rustc --lib --crate-type staticlib --profile apple --no-default-features --features ffi --target $t
  ls -l target/$t/apple/libmaski.a
done
D=target/apple-linktest; mkdir -p $D
cat > $D/main.c <<'C'
#include <stdio.h>
#include "maski.h"
static void on_event(void *ctx, int32_t kind, const char *json) { printf("event %d %s\n", kind, json); }
int main(void) {
    MaskiHandle *h = maski_start("{\"server\":\"not an address\",\"pin\":\"any\",\"user\":\"u\",\"pass\":\"p\"}", -1, NULL, on_event, NULL);
    printf("handle %p (NULL expected: bad config)\n", (void *)h);
    MaskiStats s; printf("stats %d\n", maski_stats(h, &s));
    maski_stop(h);
    return h != NULL;
}
C
xcrun --sdk iphoneos clang -target arm64-apple-ios15.0 -Iinclude $D/main.c target/aarch64-apple-ios/apple/libmaski.a \
  -framework Security -framework CoreFoundation -o $D/linktest-ios
xcrun --sdk macosx clang -target arm64-apple-macos12 -Iinclude $D/main.c target/aarch64-apple-darwin/apple/libmaski.a \
  -framework Security -framework CoreFoundation -o $D/linktest-mac
file $D/linktest-ios $D/linktest-mac
$D/linktest-mac
