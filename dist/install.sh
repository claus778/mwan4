#!/bin/sh
# MWAN4 離線安裝腳本
#
# 安全注意：只接受「腳本所在目錄」或命令列明確指定的 bundle。
# 舊版會自動從 /tmp 取 mwan4-*-bundle.tar.gz —— /tmp 是 1777，任何本機使用者
# 都能預置一個含惡意 /usr/bin/mwan4 的 tar，管理員一執行 install.sh 就以 root
# 解壓並執行，等同本機提權。這裡同時拒絕含絕對路徑或 .. 的 tar 成員。
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

# 完整性檢查：同目錄有 SHA256SUMS 就必須通過（bundle 未簽名，這只防傳輸損壞/誤放）
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

# 解壓前拒絕絕對路徑與 .. 成員
if tar -tzf "$BUNDLE" | grep -Eq '^/|(^|/)\.\.(/|$)'; then
    echo "Error: $BUNDLE_NAME contains unsafe paths, refusing to extract" >&2
    exit 1
fi

echo "==> Installing MWAN4 from $BUNDLE ..."

# 先備份既有設定：bundle 內含出廠預設設定，直接解壓會覆蓋使用者調整過的內容
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

# 還原使用者設定（存在才還原；全新安裝則採用 bundle 內的預設值）
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
