"""Probe Microsoft symbol server for F4 EXE PDBs.

Reads the CodeView debug directory (GUID + Age + PDB filename) from each PE,
queries https://msdl.microsoft.com/download/symbols/<pdb>/<guid><age>/<pdb>.
Prints HEAD status (200 / 404) — we don't download, just verify availability.
"""
import os, struct, urllib.request, urllib.error

BINARIES = [
    ('F4 OG 1.10.163', r'C:\Games\Fallout.4 1.10.163\Fallout4.exe'),
    ('F4 NG 1.10.980', r'C:\Games\Fallout4 1.10.980\Fallout4.exe'),
    ('F4 NG unpacked', r'C:\Games\Steam\steamapps\content\app_377160\depot_377162\Fallout4.exe.unpacked.exe'),
    ('F4 AE unpacked', r'C:\Games\Steam\steamapps\common\Fallout 4 AE\Fallout4.exe.unpacked.exe'),
    ('F4 VR unpacked', r'C:\Games\Steam\steamapps\common\Fallout 4 VR\Fallout4VR.exe.unpacked.exe'),
]

SYMBOL_SERVER = 'https://msdl.microsoft.com/download/symbols'


def _read_pe_codeview(path):
    """Return (pdb_name, guid_age_str) from CodeView RSDS entry, or None."""
    with open(path, 'rb') as fh:
        data = fh.read()
    if data[:2] != b'MZ':
        return None
    pe_off = struct.unpack_from('<I', data, 0x3c)[0]
    if data[pe_off:pe_off + 4] != b'PE\0\0':
        return None
    # COFF header at pe_off+4; optional header follows; magic at +0x18.
    opt_magic = struct.unpack_from('<H', data, pe_off + 0x18)[0]
    is_pe32p = (opt_magic == 0x20b)
    # Debug directory is DataDirectory index 6; DataDir array starts at
    # optional-header offset 0x60 (PE32) or 0x70 (PE32+).
    dd_off = pe_off + 0x18 + (0x70 if is_pe32p else 0x60)
    debug_rva = struct.unpack_from('<I', data, dd_off + 6 * 8)[0]
    debug_size = struct.unpack_from('<I', data, dd_off + 6 * 8 + 4)[0]
    if not debug_rva or not debug_size:
        return None
    # Map RVA->file offset via sections.
    nsec = struct.unpack_from('<H', data, pe_off + 6)[0]
    sec_off = pe_off + 0x18 + (0xf0 if is_pe32p else 0xe0)
    sections = []
    for i in range(nsec):
        s = sec_off + i * 0x28
        v_size = struct.unpack_from('<I', data, s + 8)[0]
        v_rva = struct.unpack_from('<I', data, s + 12)[0]
        r_size = struct.unpack_from('<I', data, s + 16)[0]
        r_off = struct.unpack_from('<I', data, s + 20)[0]
        sections.append((v_rva, v_size, r_off, r_size))

    def rva_to_off(rva):
        for v_rva, v_size, r_off, r_size in sections:
            if v_rva <= rva < v_rva + max(v_size, r_size):
                return r_off + (rva - v_rva)
        return None

    deb_file = rva_to_off(debug_rva)
    if deb_file is None:
        return None
    for i in range(debug_size // 0x1c):
        entry = deb_file + i * 0x1c
        dbg_type = struct.unpack_from('<I', data, entry + 12)[0]
        dbg_size = struct.unpack_from('<I', data, entry + 16)[0]
        dbg_rva = struct.unpack_from('<I', data, entry + 20)[0]
        dbg_off = struct.unpack_from('<I', data, entry + 24)[0]
        if dbg_type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            cv = data[dbg_off:dbg_off + dbg_size]
            if cv[:4] != b'RSDS':
                continue
            guid_bytes = cv[4:20]
            age = struct.unpack_from('<I', cv, 20)[0]
            name_end = cv.find(b'\0', 24)
            pdb_name = cv[24:name_end].decode('utf-8', errors='replace')
            d1 = struct.unpack_from('<I', guid_bytes, 0)[0]
            d2 = struct.unpack_from('<H', guid_bytes, 4)[0]
            d3 = struct.unpack_from('<H', guid_bytes, 6)[0]
            rest = ''.join('{:02X}'.format(b) for b in guid_bytes[8:])
            guid_str = '{:08X}{:04X}{:04X}{}'.format(d1, d2, d3, rest)
            return (os.path.basename(pdb_name), '{}{:X}'.format(guid_str, age))
    return None


def probe(pdb_name, guid_age):
    url = '{}/{}/{}/{}'.format(SYMBOL_SERVER, pdb_name, guid_age, pdb_name)
    req = urllib.request.Request(url, method='HEAD',
                                 headers={'User-Agent': 'Microsoft-Symbol-Server/10.0'})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, url
    except urllib.error.HTTPError as e:
        return e.code, url
    except Exception as e:
        return 'ERR:{}'.format(e), url


if __name__ == '__main__':
    for label, path in BINARIES:
        if not os.path.isfile(path):
            print('{:20s} MISSING {}'.format(label, path))
            continue
        info = _read_pe_codeview(path)
        if info is None:
            print('{:20s} NO_CODEVIEW'.format(label))
            continue
        pdb_name, guid_age = info
        status, url = probe(pdb_name, guid_age)
        print('{:20s} {} {:<40s} {}'.format(label, status, pdb_name, url))
