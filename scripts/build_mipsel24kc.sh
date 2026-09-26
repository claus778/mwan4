#!/bin/bash
# 交叉编译 mipsel_24kc（ramips / MT7621 等，OpenWrt 的 arch 名）用的 mwan4 静态二进位。
#
# 为什么需要这支脚本：`mipsel-unknown-linux-musl` 是 **tier-3** 目标，rustup 没有预编译 std
# （`rustup target add mipsel-unknown-linux-musl` 会回 "has no prebuilt artifacts"），所以必须：
#   1. `-Z build-std=std,panic_abort` 从 rust-src 现场编 std；
#   2. 自备 musl sysroot（crt1.o/crti.o/crtn.o/libc.a）与连结驱动 —— 用 musl.cc 的
#      `mipsel-linux-muslsf-gcc`（soft-float；MT7621/24Kc 没有 FPU，rustc 这个 target 的预设
#      特性也是 +soft-float，用 hard-float 的 musl 会出现 -mhard-float/-msoft-float ABI 冲突）。
#
# 四个实测踩到的坑（都在下面处理掉了）：
#   a. 这个 target 的 spec 是 `dynamic-linking: true` 且没有 +crt-static —— 不显式加
#      `-C target-feature=+crt-static` 会编出「依赖装置 musl 载入器」的动态档；
#   b. 静态连结时 rustc 会把 crt1.o/crti.o/crtbegin.o/crtend.o/crtn.o 以**裸档名**丢给 cc
#      并附带 `-nostartfiles`（tier-3 没有 self-contained 目录）——而 GNU ld 对「明确档名」
#      只查 CWD、**不查 -L**，所以 -L 再多也没用，必须由 wrapper 补成绝对路径；
#   c. 同一条路径上 rustc 固定会加 `-lunwind`，而 musl.cc 的工具链没有打包 libunwind
#      （只有 libgcc_eh.a）。两者都是 Itanium ABI 的 `_Unwind_*`，故把 libgcc_eh.a 以
#      libunwind.a 之名放进私有 lib 目录（本专案 panic=abort，unwinder 实际不会被呼叫）；
#   d. gcc 预设 --enable-default-pie，rustc 又会给 `-static -no-pie`，因此 crtbegin.o/crtend.o
#      （非 S 版）也要一起补路径。
#
# 前置环境（Windows 工作站）： scripts/wsl-mipsel-setup.sh
#   wsl -d Debian -- bash /mnt/d/编程/mwan4/scripts/wsl-mipsel-setup.sh
#
# 用法：
#   wsl -d Debian -- bash /mnt/d/编程/mwan4/scripts/build_mipsel24kc.sh
# 产物：
#   target/mipsel-unknown-linux-musl/release/mwan4（静态、soft-float，可直接喂给
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
# 放家目录（ext4）而不是 /mnt/d：9p 档案系统上的 target/ 会慢好几倍
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/mwan4-target-mipsel}"
export PATH="$HOME/.cargo/bin:$TOOLCHAIN_BIN:$PATH"
# 本仓库 .cargo/config.toml 为这台工作站写死了 http://127.0.0.1:7893 这个本机代理；
# 代理没开时 cargo 会直接失败。预设清空（要用的话设 MWAN4_HTTP_PROXY）。
export CARGO_HTTP_PROXY="${MWAN4_HTTP_PROXY:-}"
# `-Z build-std` 是 nightly 功能；RUSTC_BOOTSTRAP=1 只解锁这类 -Z 开关，不改语言特性
export RUSTC_BOOTSTRAP=1

command -v cargo >/dev/null || { echo "找不到 cargo（先跑 scripts/wsl-mipsel-setup.sh）" >&2; exit 1; }
[ -x "$GCC" ] || { echo "找不到 $GCC（先跑 scripts/wsl-mipsel-setup.sh）" >&2; exit 1; }

GCC_LIB="$("$GCC" -print-libgcc-file-name | xargs -r dirname)"
mkdir -p "$SHIM_LIB"
cp -f "$GCC_LIB/libgcc_eh.a" "$SHIM_LIB/libunwind.a"

cat > "$LINK_WRAPPER" <<'WRAPPER'
#!/bin/bash
# 由 scripts/build_mipsel24kc.sh 生成：rustc 会把 crt1.o/crti.o/crtbegin.o/crtend.o/crtn.o
# 以裸档名交给 cc（并带 -nostartfiles），而 GNU ld 对「明确档名」只查 CWD、不查 -L，
# 所以这里把它们补成绝对路径。注意 heredoc 用引号（不展开），路径由 wrapper 自己定位。
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

# 只对这个 target 生效（不要用 RUSTFLAGS，避免污染 host build script 的连结）
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

echo "==> 产物 $OUT ($(stat -c%s "$OUT") bytes)"
sha256sum "$OUT"
if command -v readelf >/dev/null; then
  readelf -h "$OUT" | grep -E "Class|Machine|Flags"
  readelf -A "$OUT" | grep -Ei "FP ABI" || true
  if readelf -lW "$OUT" | grep -q INTERP; then
    echo "!! 动态连结（有 PT_INTERP）；这个部署要的是静态" >&2; exit 1
  fi
  echo "OK: 静态连结"
fi
