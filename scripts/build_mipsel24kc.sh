#!/bin/bash
# 交叉編譯 mipsel_24kc（ramips / MT7621 等，OpenWrt 的 arch 名）用的 mwan4 靜態二進位。
#
# 為什麼需要這支腳本：`mipsel-unknown-linux-musl` 是 **tier-3** 目標，rustup 沒有預編譯 std
# （`rustup target add mipsel-unknown-linux-musl` 會回 "has no prebuilt artifacts"），所以必須：
#   1. `-Z build-std=std,panic_abort` 從 rust-src 現場編 std；
#   2. 自備 musl sysroot（crt1.o/crti.o/crtn.o/libc.a）與連結驅動 —— 用 musl.cc 的
#      `mipsel-linux-muslsf-gcc`（soft-float；MT7621/24Kc 沒有 FPU，rustc 這個 target 的預設
#      特性也是 +soft-float，用 hard-float 的 musl 會出現 -mhard-float/-msoft-float ABI 衝突）。
#
# 四個實測踩到的坑（都在下面處理掉了）：
#   a. 這個 target 的 spec 是 `dynamic-linking: true` 且沒有 +crt-static —— 不顯式加
#      `-C target-feature=+crt-static` 會編出「依賴裝置 musl 載入器」的動態檔；
#   b. 靜態連結時 rustc 會把 crt1.o/crti.o/crtbegin.o/crtend.o/crtn.o 以**裸檔名**丟給 cc
#      並附帶 `-nostartfiles`（tier-3 沒有 self-contained 目錄）——而 GNU ld 對「明確檔名」
#      只查 CWD、**不查 -L**，所以 -L 再多也沒用，必須由 wrapper 補成絕對路徑；
#   c. 同一條路徑上 rustc 固定會加 `-lunwind`，而 musl.cc 的工具鏈沒有打包 libunwind
#      （只有 libgcc_eh.a）。兩者都是 Itanium ABI 的 `_Unwind_*`，故把 libgcc_eh.a 以
#      libunwind.a 之名放進私有 lib 目錄（本專案 panic=abort，unwinder 實際不會被呼叫）；
#   d. gcc 預設 --enable-default-pie，rustc 又會給 `-static -no-pie`，因此 crtbegin.o/crtend.o
#      （非 S 版）也要一起補路徑。
#
# 前置環境（Windows 工作站）： scripts/wsl-mipsel-setup.sh
#   wsl -d Debian -- bash /mnt/d/编程/mwan4/scripts/wsl-mipsel-setup.sh
#
# 用法：
#   wsl -d Debian -- bash /mnt/d/编程/mwan4/scripts/build_mipsel24kc.sh
# 產物：
#   target/mipsel-unknown-linux-musl/release/mwan4（靜態、soft-float，可直接餵給
#   scripts/build_packages.py --arch mipsel_24kc）
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET=mipsel-unknown-linux-musl
PREFIX="${MWAN4_MIPSEL_PREFIX:-$HOME/toolchains}"
TOOLCHAIN_DIR="$PREFIX/mipsel-linux-muslsf-cross"
TOOLCHAIN_BIN="$TOOLCHAIN_DIR/bin"
GCC="$TOOLCHAIN_BIN/mipsel-linux-muslsf-gcc"
SYSROOT_LIB="$TOOLCHAIN_DIR/mipsel-linux-muslsf/lib"
SHIM_LIB="$PREFIX/muslsf-shim-lib"
LINK_WRAPPER="$PREFIX/mipsel-muslsf-cc.sh"
# 放家目錄（ext4）而不是 /mnt/d：9p 檔案系統上的 target/ 會慢好幾倍
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/mwan4-target-mipsel}"
export PATH="$HOME/.cargo/bin:$TOOLCHAIN_BIN:$PATH"
# 本倉庫 .cargo/config.toml 為這台工作站寫死了 http://127.0.0.1:7893 這個本機代理；
# 代理沒開時 cargo 會直接失敗。預設清空（要用的話設 MWAN4_HTTP_PROXY）。
export CARGO_HTTP_PROXY="${MWAN4_HTTP_PROXY:-}"
# `-Z build-std` 是 nightly 功能；RUSTC_BOOTSTRAP=1 只解鎖這類 -Z 開關，不改語言特性
export RUSTC_BOOTSTRAP=1

command -v cargo >/dev/null || { echo "找不到 cargo（先跑 scripts/wsl-mipsel-setup.sh）" >&2; exit 1; }
[ -x "$GCC" ] || { echo "找不到 $GCC（先跑 scripts/wsl-mipsel-setup.sh）" >&2; exit 1; }

GCC_LIB="$("$GCC" -print-libgcc-file-name | xargs -r dirname)"
mkdir -p "$SHIM_LIB"
cp -f "$GCC_LIB/libgcc_eh.a" "$SHIM_LIB/libunwind.a"

cat > "$LINK_WRAPPER" <<'WRAPPER'
#!/bin/bash
# 由 scripts/build_mipsel24kc.sh 生成：rustc 會把 crt1.o/crti.o/crtbegin.o/crtend.o/crtn.o
# 以裸檔名交給 cc（並帶 -nostartfiles），而 GNU ld 對「明確檔名」只查 CWD、不查 -L，
# 所以這裡把它們補成絕對路徑。注意 heredoc 用引號（不展開），路徑由 wrapper 自己定位。
set -euo pipefail
PREFIX="$(dirname "$(realpath "$0")")"
GCC="$PREFIX/mipsel-linux-muslsf-cross/bin/mipsel-linux-muslsf-gcc"
SYSROOT_LIB="$PREFIX/mipsel-linux-muslsf-cross/mipsel-linux-muslsf/lib"
GCC_LIB="$("$GCC" -print-libgcc-file-name | xargs -r dirname)"
args=()
for a in "$@"; do
  case "$a" in
    crt1.o|crti.o|crtn.o) args+=("$SYSROOT_LIB/$a") ;;
    crtbegin.o|crtbeginS.o|crtend.o|crtendS.o) args+=("$GCC_LIB/$a") ;;
    *) args+=("$a") ;;
  esac
done
exec "$GCC" "${args[@]}"
WRAPPER
chmod +x "$LINK_WRAPPER"

cd "$REPO_DIR"
echo "==> cargo $(cargo --version) / muslsf-gcc $("$GCC" -dumpversion) / libgcc $GCC_LIB =="
echo "==> linker wrapper: $LINK_WRAPPER"

# 只對這個 target 生效（不要用 RUSTFLAGS，避免污染 host build script 的連結）
export CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_RUSTFLAGS="\
-C target-feature=+crt-static \
-C link-arg=-L$SYSROOT_LIB \
-C link-arg=-L$GCC_LIB \
-C link-arg=-L$SHIM_LIB"

cargo build --release --target "$TARGET" \
  -Z build-std=std,panic_abort \
  --config "target.$TARGET.linker=\"$LINK_WRAPPER\"" \
  "$@"

BIN="$CARGO_TARGET_DIR/$TARGET/release/mwan4"
OUT="$REPO_DIR/target/$TARGET/release/mwan4"
mkdir -p "$(dirname "$OUT")"
cp -f "$BIN" "$OUT"

echo "==> 產物 $OUT ($(stat -c%s "$OUT") bytes)"
sha256sum "$OUT"
if command -v readelf >/dev/null; then
  readelf -h "$OUT" | grep -E "Class|Machine|Flags"
  readelf -A "$OUT" | grep -Ei "FP ABI" || true
  if readelf -lW "$OUT" | grep -q INTERP; then
    echo "!! 動態連結（有 PT_INTERP）；這個部署要的是靜態" >&2; exit 1
  fi
  echo "OK: 靜態連結"
fi
