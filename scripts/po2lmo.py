#!/usr/bin/env python3
import sys
import struct
import re

def sfh_hash(data: bytes, init: int = None) -> int:
    if init is None:
        init = len(data)
    length = len(data)
    if length <= 0:
        return 0
    rem = length & 3
    blocks = length >> 2
    hash_val = init & 0xFFFFFFFF
    
    idx = 0
    for _ in range(blocks):
        d0 = data[idx] | (data[idx+1] << 8)
        d1 = data[idx+2] | (data[idx+3] << 8)
        idx += 4
        hash_val = (hash_val + d0) & 0xFFFFFFFF
        tmp = ((d1 << 11) ^ hash_val) & 0xFFFFFFFF
        hash_val = ((hash_val << 16) ^ tmp) & 0xFFFFFFFF
        hash_val = (hash_val + (hash_val >> 11)) & 0xFFFFFFFF

    if rem == 3:
        d0 = data[idx] | (data[idx+1] << 8)
        c2 = struct.unpack('b', bytes([data[idx+2]]))[0]
        hash_val = (hash_val + d0) & 0xFFFFFFFF
        hash_val = (hash_val ^ (hash_val << 16)) & 0xFFFFFFFF
        hash_val = (hash_val ^ ((c2 << 18) & 0xFFFFFFFF)) & 0xFFFFFFFF
        hash_val = (hash_val + (hash_val >> 11)) & 0xFFFFFFFF
    elif rem == 2:
        d0 = data[idx] | (data[idx+1] << 8)
        hash_val = (hash_val + d0) & 0xFFFFFFFF
        hash_val = (hash_val ^ (hash_val << 11)) & 0xFFFFFFFF
        hash_val = (hash_val + (hash_val >> 17)) & 0xFFFFFFFF
    elif rem == 1:
        c0 = struct.unpack('b', bytes([data[idx]]))[0]
        hash_val = (hash_val + c0) & 0xFFFFFFFF
        hash_val = (hash_val ^ (hash_val << 10)) & 0xFFFFFFFF
        hash_val = (hash_val + (hash_val >> 1)) & 0xFFFFFFFF

    hash_val = (hash_val ^ (hash_val << 3)) & 0xFFFFFFFF
    hash_val = (hash_val + (hash_val >> 5)) & 0xFFFFFFFF
    hash_val = (hash_val ^ (hash_val << 4)) & 0xFFFFFFFF
    hash_val = (hash_val + (hash_val >> 17)) & 0xFFFFFFFF
    hash_val = (hash_val ^ (hash_val << 25)) & 0xFFFFFFFF
    hash_val = (hash_val + (hash_val >> 6)) & 0xFFFFFFFF
    return hash_val

def unescape_po(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            c = s[i+1]
            if c == 'n':
                out.append('\n')
            elif c == 't':
                out.append('\t')
            elif c == 'r':
                out.append('\r')
            elif c == '"':
                out.append('"')
            elif c == '\\':
                out.append('\\')
            else:
                out.append(c)
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)

def parse_po(filename):
    entries = []
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()

    current_msg = {"ctxt": None, "id": None, "str": None}
    state = None

    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        m_ctxt = re.match(r'^msgctxt\s+"(.*)"$', line)
        m_id = re.match(r'^msgid\s+"(.*)"$', line)
        m_str = re.match(r'^msgstr\s+"(.*)"$', line)
        m_cont = re.match(r'^"(.*)"$', line)

        if m_ctxt:
            if current_msg["id"] is not None and current_msg["str"] is not None:
                entries.append(current_msg)
                current_msg = {"ctxt": None, "id": None, "str": None}
            current_msg["ctxt"] = unescape_po(m_ctxt.group(1))
            state = "ctxt"
        elif m_id:
            if current_msg["id"] is not None and current_msg["str"] is not None:
                entries.append(current_msg)
                current_msg = {"ctxt": None, "id": None, "str": None}
            current_msg["id"] = unescape_po(m_id.group(1))
            state = "id"
        elif m_str:
            current_msg["str"] = unescape_po(m_str.group(1))
            state = "str"
        elif m_cont:
            val = unescape_po(m_cont.group(1))
            if state == "ctxt":
                current_msg["ctxt"] += val
            elif state == "id":
                current_msg["id"] += val
            elif state == "str":
                current_msg["str"] += val

    if current_msg["id"] is not None and current_msg["str"] is not None:
        entries.append(current_msg)

    return entries

def convert_po_to_lmo(po_file, lmo_file):
    entries = parse_po(po_file)
    data_bytes = bytearray()
    index_entries = []

    for item in entries:
        msg_id = item["id"]
        msg_str = item["str"]
        msg_ctxt = item["ctxt"]

        if msg_id == "":
            # Header, look for Plural-Forms
            m = re.search(r'Plural-Forms:\s*([^\r\n]+)', msg_str, re.IGNORECASE)
            if m:
                pf = m.group(1).strip()
                if pf.endswith(';'):
                    val_bytes = pf.encode('utf-8')
                else:
                    val_bytes = (pf + ';').encode('utf-8')
                length = len(val_bytes)
                offset = len(data_bytes)
                data_bytes.extend(val_bytes)
                pad = (4 - (length % 4)) % 4
                data_bytes.extend(b'\x00' * pad)
                index_entries.append((0, 0, offset, length))
            continue

        if not msg_str:
            continue

        if msg_ctxt:
            key = f"{msg_ctxt}\x01{msg_id}"
        else:
            key = msg_id

        key_bytes = key.encode('utf-8')
        val_bytes = msg_str.encode('utf-8')

        key_id = sfh_hash(key_bytes)
        val_id = sfh_hash(val_bytes)

        length = len(val_bytes)
        offset = len(data_bytes)
        data_bytes.extend(val_bytes)
        pad = (4 - (length % 4)) % 4
        data_bytes.extend(b'\x00' * pad)
        index_entries.append((key_id, 1, offset, length))

    # Sort index by key_id
    index_entries.sort(key=lambda x: x[0])

    # Index starts right after data_bytes
    index_offset = len(data_bytes)
    for k_id, v_id, off, length in index_entries:
        data_bytes.extend(struct.pack('>IIII', k_id, v_id, off, length))

    # Write index_offset at the very end
    data_bytes.extend(struct.pack('>I', index_offset))

    with open(lmo_file, 'wb') as f:
        f.write(data_bytes)
    print(f"Generated {lmo_file} with {len(index_entries)} translations (index offset: {index_offset}).")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.po> <output.lmo>")
        sys.exit(1)
    convert_po_to_lmo(sys.argv[1], sys.argv[2])
