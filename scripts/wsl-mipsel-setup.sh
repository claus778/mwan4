#!/bin/bash
# 一次性環境：在 WSL Debian 內準備 mipsel_24kc 交叉編譯環境
#   1) rustup（stable + rust-src，供 -Z build-std 使用）
#   2) musl.cc 的 mipsel-linux-musl 交叉工具鏈（crt1.o / libc.a + 連結驅動）
#
# 注意：**不要裝到 /opt** —— WSL 預設使用者不是 root，tar 會以
# "Cannot mkdir: No such file or directory" 之類的訊息失敗。裝在使用者家目錄最省事。
set -euo pipefail

# ⚠️ 一定要用 **muslsf**（soft-float）那個：MT7621/24Kc 沒有 FPU，OpenWrt 的 mipsel_24kc
# 也是 soft-float；musl.cc 的 mipsel-linux-musl（沒有 sf）是 hard-float 的 CRT/libc，
# 連結時會出現 "-mhard-float ... uses -msoft-float" 的 ABI 衝突。
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

echo "==> 2/3 musl 交叉工具鏈 -> $TOOLCHAIN_DIR"
if [ ! -x "$TOOLCHAIN_DIR/bin/mipsel-linux-muslsf-gcc" ]; then
  mkdir -p "$PREFIX"
  tar -xzf "$TOOLCHAIN_TGZ" -C "$PREFIX"
fi
"$TOOLCHAIN_DIR/bin/mipsel-linux-muslsf-gcc" --version | head -1

echo "==> 3/3 完成（build-mipsel.sh 會自己把 bin 加進 PATH）"
