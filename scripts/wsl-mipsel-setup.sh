#!/bin/bash
# 一次性环境：在 WSL Debian 内准备 mipsel_24kc 交叉编译环境
#   1) rustup（stable + rust-src，供 -Z build-std 使用）
#   2) musl.cc 的 mipsel-linux-musl 交叉工具链（crt1.o / libc.a + 连结驱动）
#
# 注意：**不要装到 /opt** —— WSL 预设使用者不是 root，tar 会以
# "Cannot mkdir: No such file or directory" 之类的讯息失败。装在使用者家目录最省事。
set -euo pipefail

# ⚠️ 一定要用 **muslsf**（soft-float）那个：MT7621/24Kc 没有 FPU，OpenWrt 的 mipsel_24kc
# 也是 soft-float；musl.cc 的 mipsel-linux-musl（没有 sf）是 hard-float 的 CRT/libc，
# 连结时会出现 "-mhard-float ... uses -msoft-float" 的 ABI 冲突。
TOOLCHAIN_TGZ="${TOOLCHAIN_TGZ:-/mnt/d/toolchains/mipsel-linux-muslsf-cross.tgz}"
PREFIX="${PREFIX:-$HOME/toolchains}"
TOOLCHAIN_DIR="$PREFIX/mipsel-linux-muslsf-cross"

echo "==> 1/3 rustup"
if [ ! -x "$HOME/.cargo/bin/cargo" ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path
fi
"$HOME/.cargo/bin/rustup" component add rust-src
"$HOME/.cargo/bin/rustc" --version

echo "==> 2/3 musl 交叉工具链 -> $TOOLCHAIN_DIR"
if [ ! -x "$TOOLCHAIN_DIR/bin/mipsel-linux-muslsf-gcc" ]; then
  mkdir -p "$PREFIX"
  tar -xzf "$TOOLCHAIN_TGZ" -C "$PREFIX"
fi
"$TOOLCHAIN_DIR/bin/mipsel-linux-muslsf-gcc" --version | head -1

echo "==> 3/3 完成（build-mipsel.sh 会自己把 bin 加进 PATH）"
