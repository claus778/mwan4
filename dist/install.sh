#!/bin/sh
# MWAN4 离线安装脚本
#
# 安全注意：只接受「脚本所在目录」或命令列明确指定的 bundle。
# 旧版会自动从 /tmp 取 mwan4-*-bundle.tar.gz —— /tmp 是 1777，任何本机使用者
# 都能预置一个含恶意 /usr/bin/mwan4 的 tar，管理员一执行 install.sh 就以 root
# 解压并执行，等同本机提权。这里同时拒绝含绝对路径或 .. 的 tar 成员。
set -e

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
BUNDLE=""

if [ -n "$1" ]; then
    BUNDLE="$1"
else
    for candidate in "$SCRIPT_DIR"/mwan4-*-bundle.tar.gz; do
        [ -f "$candidate" ] || continue
        if [ -n "$BUNDLE" ]; then
            echo "Error: multiple bundles found in $SCRIPT_DIR; pass one explicitly" >&2
            exit 1
        fi
        BUNDLE="$candidate"
    done
fi

if [ -z "$BUNDLE" ] || [ ! -f "$BUNDLE" ]; then
    echo "Error: bundle not found." >&2
    echo "Usage: $0 [path/to/mwan4-<arch>-bundle.tar.gz]" >&2
    exit 1
fi

BUNDLE_DIR=$(CDPATH= cd "$(dirname "$BUNDLE")" && pwd)
BUNDLE_NAME=$(basename "$BUNDLE")

# 完整性检查：同目录有 SHA256SUMS 就必须通过（bundle 未签名，这只防传输损坏/误放）
if [ -f "$BUNDLE_DIR/SHA256SUMS" ]; then
    line=$(grep -F "  $BUNDLE_NAME" "$BUNDLE_DIR/SHA256SUMS" || true)
    if [ -z "$line" ]; then
        echo "Error: $BUNDLE_NAME is not listed in $BUNDLE_DIR/SHA256SUMS" >&2
        exit 1
    fi
    want=$(printf '%s\n' "$line" | cut -d' ' -f1)
    got=$(sha256sum "$BUNDLE" | cut -d' ' -f1)
    if [ "$want" != "$got" ]; then
        echo "Error: checksum verification failed for $BUNDLE_NAME" >&2
        exit 1
    fi
    echo "==> Bundle checksum verified"
fi

# 解压前拒绝绝对路径与 .. 成员
if tar -tzf "$BUNDLE" | grep -Eq '^/|(^|/)\.\.(/|$)'; then
    echo "Error: $BUNDLE_NAME contains unsafe paths, refusing to extract" >&2
    exit 1
fi

echo "==> Installing MWAN4 from $BUNDLE ..."

# 先备份既有设定：bundle 内含出厂预设设定，直接解压会覆盖使用者调整过的内容
BACKUP_DIR=/etc/mwan4/preinstall-backup
saved_uci=0
saved_json=0
if [ -f /etc/config/mwan4 ]; then
    mkdir -p "$BACKUP_DIR"
    cp -p /etc/config/mwan4 "$BACKUP_DIR/config.mwan4"
    saved_uci=1
fi
if [ -f /etc/mwan4/mwan4.json ]; then
    mkdir -p "$BACKUP_DIR"
    cp -p /etc/mwan4/mwan4.json "$BACKUP_DIR/mwan4.json"
    saved_json=1
fi

tar -xzf "$BUNDLE" -C /

# 还原使用者设定（存在才还原；全新安装则采用 bundle 内的预设值）
if [ "$saved_uci" -eq 1 ]; then
    cp -p "$BACKUP_DIR/config.mwan4" /etc/config/mwan4
fi
if [ "$saved_json" -eq 1 ]; then
    cp -p "$BACKUP_DIR/mwan4.json" /etc/mwan4/mwan4.json
fi

chmod +x /usr/bin/mwan4 /etc/init.d/mwan4

if [ -f /etc/mwan4/mwan4.json ]; then
    if ! /usr/bin/mwan4 --check-config /etc/mwan4/mwan4.json; then
        echo "Error: /etc/mwan4/mwan4.json failed validation, aborting install" >&2
        exit 1
    fi
fi

/etc/init.d/mwan4 enable
/etc/init.d/mwan4 restart
/etc/init.d/rpcd restart 2>/dev/null || true
/etc/init.d/uhttpd restart 2>/dev/null || true

echo "==> MWAN4 successfully installed and started!"
/etc/init.d/mwan4 status || true
