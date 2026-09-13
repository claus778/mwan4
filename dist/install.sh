#!/bin/sh
# MWAN4 離線安裝腳本（自動尋找 mwan4-*-bundle.tar.gz）
set -e

BUNDLE=""
for candidate in /tmp/mwan4-*-bundle.tar.gz ./mwan4-*-bundle.tar.gz; do
    if [ -f "$candidate" ]; then
        BUNDLE="$candidate"
        break
    fi
done

if [ -z "$BUNDLE" ]; then
    echo "Error: mwan4-*-bundle.tar.gz not found (looked in /tmp and current dir)" >&2
    exit 1
fi

echo "==> Installing MWAN4 from $BUNDLE ..."
tar -xzf "$BUNDLE" -C /

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
