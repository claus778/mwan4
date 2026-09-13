#!/usr/bin/env python3
"""MWAN4 打包腳本（APK + IPK + 離線 bundle）。

設計要點
--------
1. 簽名金鑰只生成一次並持久化（預設 0600），不再每次打包換一把。
   已裝機的 mwan4.rsa.pub 才能持續驗證後續版本，歷史簽名也可復現。
   - MWAN4_SIGNING_KEY=<path>     指定/生成金鑰檔的位置
   - MWAN4_SIGNING_KEY_PEM=<pem>  直接內嵌 PEM（CI / 密鑰管理用，完全不落盤）
2. 按架構出包：不再產出「標 arch = all、內容卻是 aarch64 二進位」的假通用包。
   只對「確實存在已編譯二進位」的 target 出包，檔名 / .PKGINFO / control
   全部帶上真實架構。跨架構安裝會直接被 apk / opkg 拒絕，而不是裝完才 SIGSEGV。
3. 依賴聲明（原本完全缺失）：
   - APK  : depend = libc
   - IPK  : Depends: libc
   OpenWrt/ImmortalWrt 的 libc 包名就是 `libc`（provides `libc-any`）。
   注意：**不要**照 Alpine 寫成 `so:libc.musl-<arch>.so.1` —— OpenWrt 沒有這種
   provider，依賴會無法解析、安裝直接失敗（實機踩過）。錯架構的攔阻由
   .PKGINFO 的 `arch` 欄位負責。
4. 翻譯：LuCI 的 .lmo 一律在打包時由 .po 重新編譯，不再依賴入庫的 .lmo。
   舊的 .lmo 會在 .po 變更後悄悄過期，UI 默默退回英文；改成建置時編譯後，
   出廠的翻譯必定與原始 .po 一致，並安裝到 /usr/lib/lua/luci/i18n/。
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import os
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(ROOT_DIR, "dist")
PKG_DIR = os.path.join(OUTPUT_DIR, "packages")
BIN_OUT_DIR = os.path.join(OUTPUT_DIR, "bin")
KEY_DIR = os.path.join(OUTPUT_DIR, "keys")

DEFAULT_PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "mwan4.rsa.key")
PUB_KEY_NAME = "mwan4.rsa.pub"

PKG_NAME = "mwan4"
LUCI_PKG_NAME = "luci-app-mwan4"
PKG_VERSION = "1.0.0"
# 注意：apk 對「同版本替換（1.0.0-r1 -> 1.0.0-r1）」**不會執行 post-install 鉤子**，
# 只有真正的版本升級才會跑（實機驗證）。所以只要二進位/腳本有變，就必須遞增 release。
APK_RELEASE = "r3"
IPK_RELEASE = "3"

# 新生成金鑰的位元數 / 可接受的最小位元數
KEY_SIZE = 2048
MIN_KEY_SIZE = 2048

URL = "https://github.com/mwan4/mwan4"
PACKAGER = "MWAN4 Team"
LICENSE = "MIT"


def log(msg: str) -> None:
    print(msg, flush=True)


def fatal(msg: str):
    print(f"[!] {msg}", file=sys.stderr, flush=True)
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# 架構表
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Arch:
    """一個可出包的目標架構。"""

    #: 供 --arch 使用的短名，同時作為二進位檔名後綴
    key: str
    #: Rust target triple（用於 target/<triple>/release/mwan4）
    rust_target: str
    #: apk 的 arch 欄位（OpenWrt 風格）
    apk_arch: str
    #: ipk 的 Architecture 欄位
    ipk_arch: str
    #: apk 的 libc 依賴。OpenWrt/ImmortalWrt 的 libc 包就叫 `libc`（provides `libc-any`），
    #: 並沒有 Alpine 那種 `so:libc.musl-<arch>.so.1` provider，因此這裡用裸包名。
    #: 錯架構的攔阻靠 .PKGINFO 的 `arch` 欄位，而不是這個依賴。
    libc_dep: str

    def binary_path(self) -> str:
        return os.path.join(ROOT_DIR, "target", self.rust_target, "release", PKG_NAME)


#: 目前支援的架構。新增架構只需在此加一行（rust target 需先 rustup target add）。
ARCH_TABLE: list[Arch] = [
    Arch(
        key="aarch64_cortex-a53",
        rust_target="aarch64-unknown-linux-musl",
        apk_arch="aarch64_cortex-a53",
        ipk_arch="aarch64_cortex-a53",
        libc_dep="libc",
    ),
    Arch(
        key="x86_64",
        rust_target="x86_64-unknown-linux-musl",
        apk_arch="x86_64",
        ipk_arch="x86_64",
        libc_dep="libc",
    ),
    Arch(
        key="arm_cortex-a7",
        rust_target="armv7-unknown-linux-musleabihf",
        apk_arch="arm_cortex-a7",
        ipk_arch="arm_cortex-a7",
        libc_dep="libc",
    ),
]
ARCH_BY_KEY = {a.key: a for a in ARCH_TABLE}


# ---------------------------------------------------------------------------
# 簽名金鑰：只生成一次、持久化、可從環境變數傳入
# ---------------------------------------------------------------------------


def _decode_private_key(pem: bytes, origin: str) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except Exception as e:  # noqa: BLE001 - 需要把底層錯誤原樣呈現給使用者
        fatal(f"failed to load signing key from {origin}: {e}")

    if not isinstance(key, rsa.RSAPrivateKey):
        fatal(f"signing key from {origin} is not an RSA private key "
              f"(got {type(key).__name__}); apk-tools only supports RSA here")
    if key.key_size < MIN_KEY_SIZE:
        fatal(f"signing key from {origin} is only {key.key_size} bits, "
              f"refusing to use anything below {MIN_KEY_SIZE}")
    return key


def _enforce_private_key_permissions(path: str) -> None:
    """私鑰必須是 0600；若權限過寬則就地收緊，避免簽名金鑰被其他行程讀走。"""
    if os.name != "posix":
        return
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        return
    if mode & 0o077:
        log(f"[!] Signing key {path} has loose permissions {mode:04o}, tightening to 0600")
        try:
            os.chmod(path, 0o600)
        except OSError as e:
            fatal(f"cannot chmod {path} to 0600: {e}")


def load_or_create_signing_key() -> tuple[rsa.RSAPrivateKey, str]:
    """取得簽名私鑰。

    優先序：MWAN4_SIGNING_KEY_PEM（記憶體） > MWAN4_SIGNING_KEY（路徑） >
    預設路徑（存在則沿用，不存在則生成）。
    """
    inline = os.environ.get("MWAN4_SIGNING_KEY_PEM")
    if inline:
        log("[key] Using in-memory signing key from MWAN4_SIGNING_KEY_PEM (not persisted)")
        return _decode_private_key(inline.encode(), "MWAN4_SIGNING_KEY_PEM"), "<in-memory>"

    path = os.environ.get("MWAN4_SIGNING_KEY") or DEFAULT_PRIVATE_KEY_PATH

    if os.path.exists(path):
        with open(path, "rb") as f:
            pem = f.read()
        key = _decode_private_key(pem, path)
        _enforce_private_key_permissions(path)
        log(f"[key] Reusing existing signing key: {path}")
        return key, path

    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # O_EXCL：若同時有兩個打包行程在跑，後到的那個會直接失敗而不是默默覆蓋金鑰
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        log(f"[key] Signing key appeared concurrently, reusing: {path}")
        with open(path, "rb") as f:
            return _decode_private_key(f.read(), path), path

    try:
        os.write(fd, pem)
    finally:
        os.close(fd)
    if os.name == "posix":
        os.chmod(path, 0o600)

    log(f"[key] Generated NEW signing key (keep this file!): {path} (0600)")
    return key, path


def public_key_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_fingerprint(key: rsa.RSAPrivateKey) -> str:
    der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


# ---------------------------------------------------------------------------
# tar / gzip 低階工具
# ---------------------------------------------------------------------------


def make_ustar_header(name: str, size: int, mode: int, typeflag: bytes = b"0") -> bytes:
    """生成標準 POSIX ustar 512 位元組頭部"""
    h = bytearray(512)
    nb = name.encode("utf-8")
    h[0:len(nb)] = nb
    h[100:108] = f"{mode:07o}\0".encode("ascii")
    h[108:116] = b"0000000\0"
    h[116:124] = b"0000000\0"
    h[124:136] = f"{size:011o}\0".encode("ascii")
    h[136:148] = f"{int(time.time()):011o}\0".encode("ascii")
    h[148:156] = b"        "
    h[156:157] = typeflag
    h[257:263] = b"ustar\0"
    h[263:265] = b"00"
    h[265:270] = b"root\0"
    h[297:302] = b"root\0"
    chk = sum(h)
    h[148:156] = f"{chk:06o}\0 ".encode("ascii")
    return bytes(h)


def pad512(data: bytes) -> bytes:
    rem = len(data) % 512
    if rem != 0:
        data += b"\0" * (512 - rem)
    return data


def compress_gz(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as f:
        f.write(data)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# 套件產生
# ---------------------------------------------------------------------------


def create_exact_apk_package(
    output_path: str,
    pkgname: str,
    pkgver: str,
    arch: str,
    desc: str,
    data_entries: list[dict],
    private_key: rsa.RSAPrivateKey,
    post_install: str | None = None,
    post_upgrade: str | None = None,
    depends: list[str] | None = None,
    provides: list[str] | None = None,
) -> None:
    """生成嚴格符合 apk-tools v2/v3 解析標準的 3-stream APK 封裝。

    Stream 1: signature tar.gz（無結尾補零塊）
    Stream 2: control tar.gz（無結尾補零塊，保證 Unix LF 換行）
    Stream 3: data tar.gz（標準 tar 格式，含 1024 位元組 EOF 塊）
    """
    # --- Stream 3 (Data) ---
    data_tar = bytearray()
    installed_size = 0
    for entry in data_entries:
        name = entry["name"]
        data = entry.get("data", b"")
        mode = entry.get("mode", 0o644)
        is_dir = entry.get("is_dir", False)

        if is_dir:
            data_tar.extend(make_ustar_header(name.rstrip("/") + "/", 0, 0o755, b"5"))
        else:
            installed_size += len(data)
            # apk-tools 3.x 要求每個檔案前必須有 PAX extended header 記錄 SHA1 校驗和
            sha1_hex = hashlib.sha1(data).hexdigest()
            pax_rec = f"68 APK-TOOLS.checksum.SHA1={sha1_hex}\n".encode("ascii")
            data_tar.extend(make_ustar_header("././@PaxHeader", len(pax_rec), 0o644, b"x"))
            data_tar.extend(pad512(pax_rec))

            data_tar.extend(make_ustar_header(name, len(data), mode, b"0"))
            data_tar.extend(pad512(data))

    data_tar.extend(b"\0" * 1024)
    data_gz_bytes = compress_gz(bytes(data_tar))
    data_sha256 = hashlib.sha256(data_gz_bytes).hexdigest()

    # --- Stream 2 (Control) ---
    pkginfo_lines = [
        f"pkgname = {pkgname}",
        f"pkgver = {pkgver}",
        f"pkgdesc = {desc}",
        f"url = {URL}",
        f"builddate = {int(time.time())}",
        f"packager = {PACKAGER}",
        f"size = {installed_size}",
        f"arch = {arch}",
        f"origin = {pkgname}",
        f"license = {LICENSE}",
    ]
    for dep in depends or []:
        pkginfo_lines.append(f"depend = {dep}")
    for prov in provides or []:
        pkginfo_lines.append(f"provides = {prov}")
    pkginfo_lines.append(f"datahash = {data_sha256}")
    pkginfo_lines.append("")
    pkginfo_bytes = "\n".join(pkginfo_lines).encode("utf-8")

    control_tar = bytearray()
    control_tar.extend(make_ustar_header(".PKGINFO", len(pkginfo_bytes), 0o644, b"0"))
    control_tar.extend(pad512(pkginfo_bytes))

    if post_install:
        pi_bytes = post_install.replace("\r\n", "\n").encode("utf-8")
        control_tar.extend(make_ustar_header(".post-install", len(pi_bytes), 0o755, b"0"))
        control_tar.extend(pad512(pi_bytes))

        # apk 在「升級」情境只會找 .post-upgrade；若不存在，它不會退回跑 .post-install，
        # 而是整個跳過（實機用 apk-tools 3.0.5 驗證過）。只發 .post-install 的結果就是：
        # 升級後二進位換了、但服務沒被重啟，仍跑著舊的 in-process 映像。
        # 因此這裡同時發出 .post-upgrade（預設與 post_install 同內容），升級與安裝都能生效。
        pu_src = post_install if post_upgrade is None else post_upgrade
        pu_bytes = pu_src.replace("\r\n", "\n").encode("utf-8")
        control_tar.extend(make_ustar_header(".post-upgrade", len(pu_bytes), 0o755, b"0"))
        control_tar.extend(pad512(pu_bytes))

    control_gz_bytes = compress_gz(bytes(control_tar))

    # --- Stream 1 (Signature) ---
    sig = private_key.sign(control_gz_bytes, padding.PKCS1v15(), hashes.SHA1())
    sig_filename = f".SIGN.RSA.{PUB_KEY_NAME}"
    sig_tar = bytearray()
    sig_tar.extend(make_ustar_header(sig_filename, len(sig), 0o644, b"0"))
    sig_tar.extend(pad512(sig))
    sig_gz_bytes = compress_gz(bytes(sig_tar))

    with open(output_path, "wb") as f:
        f.write(sig_gz_bytes)
        f.write(control_gz_bytes)
        f.write(data_gz_bytes)

    log(f"[+] Created APK: {output_path} ({os.path.getsize(output_path)} bytes, arch={arch})")


def create_ipk_package(
    output_path: str,
    pkgname: str,
    pkgver: str,
    arch: str,
    desc: str,
    data_entries: list[dict],
    postinst: str | None = None,
    depends: list[str] | None = None,
) -> None:
    """OpenWrt OPKG IPK 格式"""
    data_tar = bytearray()
    for entry in data_entries:
        name = entry["name"]
        data = entry.get("data", b"")
        mode = entry.get("mode", 0o644)
        is_dir = entry.get("is_dir", False)
        if is_dir:
            data_tar.extend(make_ustar_header(name.rstrip("/") + "/", 0, 0o755, b"5"))
        else:
            data_tar.extend(make_ustar_header(name, len(data), mode, b"0"))
            data_tar.extend(pad512(data))
    data_tar.extend(b"\0" * 1024)
    data_gz_bytes = compress_gz(bytes(data_tar))

    # control 的欄位順序有講究：Depends 必須排在 Description 之前
    control_lines = [
        f"Package: {pkgname}",
        f"Version: {pkgver}",
        f"Architecture: {arch}",
        f"Maintainer: {PACKAGER}",
        "Section: net",
        "Priority: optional",
        f"License: {LICENSE}",
    ]
    if depends:
        control_lines.append("Depends: " + ", ".join(depends))
    control_lines.append(f"Description: {desc}")
    control_content = ("\n".join(control_lines) + "\n").encode("utf-8")

    control_tar = bytearray()
    control_tar.extend(make_ustar_header("control", len(control_content), 0o644, b"0"))
    control_tar.extend(pad512(control_content))

    if postinst:
        pi_bytes = postinst.replace("\r\n", "\n").encode("utf-8")
        control_tar.extend(make_ustar_header("postinst", len(pi_bytes), 0o755, b"0"))
        control_tar.extend(pad512(pi_bytes))
    control_tar.extend(b"\0" * 1024)
    control_gz_bytes = compress_gz(bytes(control_tar))

    deb_bin = b"2.0\n"
    ipk_tar = bytearray()
    ipk_tar.extend(make_ustar_header("debian-binary", len(deb_bin), 0o644, b"0"))
    ipk_tar.extend(pad512(deb_bin))

    ipk_tar.extend(make_ustar_header("control.tar.gz", len(control_gz_bytes), 0o644, b"0"))
    ipk_tar.extend(pad512(control_gz_bytes))

    ipk_tar.extend(make_ustar_header("data.tar.gz", len(data_gz_bytes), 0o644, b"0"))
    ipk_tar.extend(pad512(data_gz_bytes))

    ipk_tar.extend(b"\0" * 1024)
    ipk_gz = compress_gz(bytes(ipk_tar))

    with open(output_path, "wb") as f:
        f.write(ipk_gz)
    log(f"[+] Created IPK: {output_path} ({os.path.getsize(output_path)} bytes, arch={arch})")


def make_tar(entries: list[dict]) -> bytes:
    tar = bytearray()
    for entry in entries:
        name = entry["name"]
        data = entry.get("data", b"")
        mode = entry.get("mode", 0o644)
        is_dir = entry.get("is_dir", False)
        if is_dir:
            tar.extend(make_ustar_header(name.rstrip("/") + "/", 0, 0o755, b"5"))
        else:
            tar.extend(make_ustar_header(name, len(data), mode, b"0"))
            tar.extend(pad512(data))
    tar.extend(b"\0" * 1024)
    return bytes(tar)


# ---------------------------------------------------------------------------
# 靜態資源
# ---------------------------------------------------------------------------

POST_INSTALL_TEMPLATE = """#!/bin/sh
[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0
# 先驗證設定檔，設定錯誤時留下明確日誌，而不是等 daemon 退出觸發 procd 重啟迴圈
if [ -x /usr/bin/mwan4 ] && [ -f /etc/mwan4/mwan4.json ]; then
    /usr/bin/mwan4 --check-config /etc/mwan4/mwan4.json >/dev/null 2>&1 || \\
        logger -t mwan4 "warning: /etc/mwan4/mwan4.json failed --check-config"
fi
/etc/init.d/mwan4 enable
/etc/init.d/mwan4 restart
exit 0
"""

LUCI_POST_INSTALL = """#!/bin/sh
[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0
/etc/init.d/rpcd restart
/etc/init.d/uhttpd restart 2>/dev/null || true
exit 0
"""

INSTALL_SH = """#!/bin/sh
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
"""


def read_file(*parts: str) -> bytes:
    path = os.path.join(*parts)
    if not os.path.exists(path):
        fatal(f"required source file missing: {path}")
    with open(path, "rb") as f:
        return f.read()


def build_mwan4_data_entries(bin_data: bytes, init_data: bytes, uci_config_data: bytes,
                             json_config_data: bytes) -> list[dict]:
    return [
        {"name": "usr", "is_dir": True},
        {"name": "usr/bin", "is_dir": True},
        {"name": "usr/bin/mwan4", "data": bin_data, "mode": 0o755},
        {"name": "etc", "is_dir": True},
        {"name": "etc/config", "is_dir": True},
        {"name": "etc/config/mwan4", "data": uci_config_data, "mode": 0o644},
        {"name": "etc/init.d", "is_dir": True},
        {"name": "etc/init.d/mwan4", "data": init_data, "mode": 0o755},
        {"name": "etc/mwan4", "is_dir": True},
        {"name": "etc/mwan4/mwan4.json", "data": json_config_data, "mode": 0o644},
    ]


def _load_po2lmo():
    """載入同目錄的 po2lmo.py（不論本腳本如何被啟動，都不能依賴 sys.path[0]）。"""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "po2lmo.py")
    if not os.path.exists(path):
        fatal(f"translation compiler not found: {path}")
    spec = importlib.util.spec_from_file_location("mwan4_po2lmo", path)
    if spec is None or spec.loader is None:
        fatal(f"cannot load translation compiler: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_lmo_bytes(po_path: str) -> bytes:
    """把 .po 編譯成 LuCI 的 .lmo，於打包時即時產生。

    刻意不讀入庫的 .lmo：那份二進位會在 .po 變更後過期，而過期不會有任何
    錯誤，UI 只是默默顯示英文。改為每次由 .po 重編，翻譯永遠與來源同步。
    """
    if not os.path.exists(po_path):
        fatal(f"translation catalog missing: {po_path}")
    po2lmo = _load_po2lmo()
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "mwan4.lmo")
        po2lmo.convert_po_to_lmo(po_path, out)
        with open(out, "rb") as f:
            return f.read()


def build_luci_data_entries(menu_data: bytes, acl_data: bytes, view_data: bytes,
                            lmo_data: bytes | None = None) -> list[dict]:
    entries = [
        {"name": "usr", "is_dir": True},
        {"name": "usr/share", "is_dir": True},
        {"name": "usr/share/luci", "is_dir": True},
        {"name": "usr/share/luci/menu.d", "is_dir": True},
        {"name": "usr/share/luci/menu.d/luci-app-mwan4.json", "data": menu_data, "mode": 0o644},
        {"name": "usr/share/rpcd", "is_dir": True},
        {"name": "usr/share/rpcd/acl.d", "is_dir": True},
        {"name": "usr/share/rpcd/acl.d/luci-app-mwan4.json", "data": acl_data, "mode": 0o644},
        {"name": "www", "is_dir": True},
        {"name": "www/luci-static", "is_dir": True},
        {"name": "www/luci-static/resources", "is_dir": True},
        {"name": "www/luci-static/resources/view", "is_dir": True},
        {"name": "www/luci-static/resources/view/mwan4", "is_dir": True},
        {"name": "www/luci-static/resources/view/mwan4/overview.js", "data": view_data, "mode": 0o644},
    ]
    if lmo_data is not None:
        entries += [
            {"name": "usr/lib", "is_dir": True},
            {"name": "usr/lib/lua", "is_dir": True},
            {"name": "usr/lib/lua/luci", "is_dir": True},
            {"name": "usr/lib/lua/luci/i18n", "is_dir": True},
            {"name": "usr/lib/lua/luci/i18n/mwan4.zh-cn.lmo", "data": lmo_data, "mode": 0o644},
        ]
    return entries


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


def resolve_archs(requested: list[str] | None) -> list[Arch]:
    """決定要為哪些架構出包。

    - 明確指定 --arch：逐一檢查二進位是否存在，缺了就報錯（不靜默跳過）。
    - 未指定：自動採用「已編譯好二進位」的架構；一個都沒有則報錯。
    """
    if requested:
        archs = []
        for key in requested:
            arch = ARCH_BY_KEY.get(key)
            if arch is None:
                fatal(
                    f"unknown architecture '{key}'. Supported: {', '.join(ARCH_BY_KEY)}"
                )
            if not os.path.exists(arch.binary_path()):
                fatal(
                    f"binary for '{key}' not found:\n    {arch.binary_path()}\n"
                    f"  build it first:  cargo build --release --target {arch.rust_target}"
                )
            archs.append(arch)
        return archs

    found = [a for a in ARCH_TABLE if os.path.exists(a.binary_path())]
    if not found:
        expected = "\n".join(f"    {a.rust_target:<34} -> {a.binary_path()}" for a in ARCH_TABLE)
        fatal(
            "no compiled mwan4 binary found for any supported architecture.\n"
            "  Build at least one first, e.g.:\n"
            "    cargo build --release --target aarch64-unknown-linux-musl\n"
            f"  Expected locations:\n{expected}"
        )
    return found


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build MWAN4 APK / IPK / offline bundle packages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  build_packages.py                        # auto: every arch with a built binary\n"
            "  build_packages.py --arch aarch64_cortex-a53\n"
            "  MWAN4_SIGNING_KEY=/etc/mwan4/signing.key build_packages.py\n"
            "  MWAN4_SIGNING_KEY_PEM=\"$(cat key.pem)\" build_packages.py\n"
        ),
    )
    parser.add_argument(
        "--arch",
        action="append",
        metavar="NAME",
        help="target architecture (repeatable). Default: auto-detect built binaries",
    )
    parser.add_argument(
        "--list-archs",
        action="store_true",
        help="list supported architectures and whether their binary is present, then exit",
    )
    parser.add_argument(
        "--key-out",
        metavar="PATH",
        help=f"where to write the public key (default: <dist>/packages/{PUB_KEY_NAME})",
    )
    args = parser.parse_args()

    if args.list_archs:
        for a in ARCH_TABLE:
            mark = "built" if os.path.exists(a.binary_path()) else "missing"
            log(f"  {a.key:<22} rust-target={a.rust_target:<34} arch(apk)={a.apk_arch:<22} [{mark}]")
        return 0

    os.makedirs(PKG_DIR, exist_ok=True)
    os.makedirs(BIN_OUT_DIR, exist_ok=True)

    # --- 1. 簽名金鑰（持久化，不再每次換） ---
    private_key, _key_origin = load_or_create_signing_key()
    pub_pem = public_key_pem(private_key)
    pub_key_path = args.key_out or os.path.join(PKG_DIR, PUB_KEY_NAME)
    with open(pub_key_path, "wb") as f:
        f.write(pub_pem)
    fingerprint = public_key_fingerprint(private_key)
    log(f"[+] Signing public key: {pub_key_path}")
    log(f"[+] Signing key SHA256: {fingerprint}")
    log("    (installed devices verify packages against this key, so it must stay stable;")
    log(f"     ship {PUB_KEY_NAME} to devices and never regenerate it without a migration plan)")

    # --- 2. 來源檔案 ---
    init_data = read_file(ROOT_DIR, "openwrt", "luci-app-mwan4", "root", "etc", "init.d", "mwan4")
    uci_config_data = read_file(ROOT_DIR, "openwrt", "luci-app-mwan4", "root", "etc", "config", "mwan4")
    json_config_data = read_file(ROOT_DIR, "openwrt", "mwan4.json")
    menu_data = read_file(ROOT_DIR, "openwrt", "luci-app-mwan4", "root", "usr", "share", "luci", "menu.d", "luci-app-mwan4.json")
    acl_data = read_file(ROOT_DIR, "openwrt", "luci-app-mwan4", "root", "usr", "share", "rpcd", "acl.d", "luci-app-mwan4.json")
    view_data = read_file(ROOT_DIR, "openwrt", "luci-app-mwan4", "htdocs", "luci-static", "resources", "view", "mwan4", "overview.js")

    # 翻譯：由 .po 即時編譯（見 build_lmo_bytes 的說明），確保出廠翻譯不落後於來源。
    lmo_data = build_lmo_bytes(os.path.join(ROOT_DIR, "openwrt", "luci-app-mwan4", "po", "zh-cn", "mwan4.po"))
    log(f"[+] Compiled translations: mwan4.zh-cn.lmo ({len(lmo_data)} bytes)")

    luci_data_entries = build_luci_data_entries(menu_data, acl_data, view_data, lmo_data)

    # --- 3. 逐架構出包（每個架構各自帶正確的 arch 與依賴） ---
    archs = resolve_archs(args.arch)
    log(f"[*] Building packages for: {', '.join(a.key for a in archs)}")

    for arch in archs:
        bin_src = arch.binary_path()
        with open(bin_src, "rb") as f:
            bin_data = f.read()

        standalone_bin = os.path.join(BIN_OUT_DIR, f"mwan4_{arch.key}")
        shutil.copy2(bin_src, standalone_bin)
        log(f"[+] Standalone binary: {standalone_bin} ({os.path.getsize(standalone_bin)} bytes)")

        data_entries = build_mwan4_data_entries(bin_data, init_data, uci_config_data, json_config_data)
        apk_ver = f"{PKG_VERSION}-{APK_RELEASE}"
        ipk_ver = f"{PKG_VERSION}-{IPK_RELEASE}"

        create_exact_apk_package(
            output_path=os.path.join(PKG_DIR, f"{PKG_NAME}_{apk_ver}_{arch.apk_arch}.apk"),
            pkgname=PKG_NAME,
            pkgver=apk_ver,
            arch=arch.apk_arch,
            desc="Ultra-lightweight Multi-WAN failover & health monitor daemon for OpenWrt",
            data_entries=data_entries,
            private_key=private_key,
            post_install=POST_INSTALL_TEMPLATE,
            depends=[arch.libc_dep],
            provides=[f"cmd:{PKG_NAME}={apk_ver}"],
        )

        create_ipk_package(
            output_path=os.path.join(PKG_DIR, f"{PKG_NAME}_{ipk_ver}_{arch.ipk_arch}.ipk"),
            pkgname=PKG_NAME,
            pkgver=ipk_ver,
            arch=arch.ipk_arch,
            desc="Ultra-lightweight Multi-WAN failover & health monitor daemon for OpenWrt",
            data_entries=data_entries,
            postinst=POST_INSTALL_TEMPLATE,
            depends=["libc"],
        )

        bundle_path = os.path.join(OUTPUT_DIR, f"mwan4-{arch.key}-bundle.tar.gz")
        with open(bundle_path, "wb") as f:
            f.write(compress_gz(make_tar(data_entries + luci_data_entries)))
        log(f"[+] Created offline bundle: {bundle_path} ({os.path.getsize(bundle_path)} bytes)")

    # --- 4. luci-app-mwan4（真正的架構無關包，apk 用 noarch / ipk 用 all） ---
    luci_apk_ver = f"{PKG_VERSION}-{APK_RELEASE}"
    luci_ipk_ver = f"{PKG_VERSION}-{IPK_RELEASE}"
    create_exact_apk_package(
        output_path=os.path.join(PKG_DIR, f"{LUCI_PKG_NAME}_{luci_apk_ver}_noarch.apk"),
        pkgname=LUCI_PKG_NAME,
        pkgver=luci_apk_ver,
        arch="noarch",
        desc="LuCI support for MWAN4 multi-WAN failover & balancing",
        data_entries=luci_data_entries,
        private_key=private_key,
        post_install=LUCI_POST_INSTALL,
        depends=[PKG_NAME],
    )

    create_ipk_package(
        output_path=os.path.join(PKG_DIR, f"{LUCI_PKG_NAME}_{luci_ipk_ver}_all.ipk"),
        pkgname=LUCI_PKG_NAME,
        pkgver=luci_ipk_ver,
        arch="all",
        desc="LuCI support for MWAN4 multi-WAN failover & balancing",
        data_entries=luci_data_entries,
        postinst=LUCI_POST_INSTALL,
        depends=[PKG_NAME],
    )

    # --- 5. 一鍵安裝腳本 ---
    install_sh_path = os.path.join(OUTPUT_DIR, "install.sh")
    with open(install_sh_path, "wb") as f:
        f.write(INSTALL_SH.replace("\r\n", "\n").encode("utf-8"))
    log(f"[+] Created one-click install script: {install_sh_path}")

    log("\nBuild complete!")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
