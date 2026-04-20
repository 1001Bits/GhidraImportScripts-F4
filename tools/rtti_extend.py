"""Extend fallout4_og_to_ae_rtti.csv to cover NG + VR.

RTTI type descriptor strings (mangled ASCII, globally unique) are trivially
locatable in any F4 binary by searching for their byte pattern in .rdata.
This driver reads the existing OG↔AE RTTI CSV and adds NG and VR columns
where the string is present, emitting fallout4_rtti_all_versions.csv.
"""
import os
import sys
import csv
import struct

BINARIES = {
    'og': r'C:\Games\Fallout.4 1.10.163\Fallout4.exe',
    'ng': r'C:\Games\Steam\steamapps\content\app_377160\depot_377162\Fallout4.exe.unpacked.exe',
    'ae': r'C:\Games\Steam\steamapps\common\Fallout 4 AE\Fallout4.exe.unpacked.exe',
    'vr': r'C:\Games\Steam\steamapps\common\Fallout 4 VR\Fallout4VR.exe.unpacked.exe',
}

IMAGE_BASE = 0x140000000


def load_pe_sections(path):
    """Return (image_base, [(section_name, v_rva, r_off, r_size)], file_bytes).

    RTTI strings on F4 NG/AE live in .data, on F4 OG/VR in .rdata — so we
    keep the whole file mapped and resolve file-offset-to-VA via any
    matching data-bearing section.
    """
    with open(path, 'rb') as fh:
        data = fh.read()
    pe_off = struct.unpack_from('<I', data, 0x3c)[0]
    opt_magic = struct.unpack_from('<H', data, pe_off + 0x18)[0]
    is_pe32p = (opt_magic == 0x20b)
    if is_pe32p:
        image_base = struct.unpack_from('<Q', data, pe_off + 0x18 + 0x18)[0]
    else:
        image_base = struct.unpack_from('<I', data, pe_off + 0x18 + 0x1c)[0]
    nsec = struct.unpack_from('<H', data, pe_off + 6)[0]
    sec_off = pe_off + 0x18 + (0xf0 if is_pe32p else 0xe0)
    sections = []
    for i in range(nsec):
        s = sec_off + i * 0x28
        name = data[s:s + 8].rstrip(b'\0').decode('ascii', errors='replace')
        v_rva = struct.unpack_from('<I', data, s + 12)[0]
        r_size = struct.unpack_from('<I', data, s + 16)[0]
        r_off = struct.unpack_from('<I', data, s + 20)[0]
        sections.append((name, v_rva, r_off, r_size))
    return image_base, sections, data


def file_off_to_va(file_off, image_base, sections):
    for name, v_rva, r_off, r_size in sections:
        if r_off <= file_off < r_off + r_size:
            return image_base + v_rva + (file_off - r_off)
    return None


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    in_csv = os.path.normpath(os.path.join(
        root, '..', '..', 'MasterModTemplate', 'Shared',
        'GhidraAnalysis', 'CrossVersionMaps', 'fallout4_og_to_ae_rtti.csv'))
    out_csv = os.path.normpath(os.path.join(
        root, '..', '..', 'MasterModTemplate', 'Shared',
        'GhidraAnalysis', 'CrossVersionMaps', 'fallout4_rtti_all_versions.csv'))

    pe = {}
    for k, path in BINARIES.items():
        if not os.path.isfile(path):
            print('{}: MISSING'.format(k))
            continue
        image_base, sections, data = load_pe_sections(path)
        pe[k] = (image_base, sections, data)
        total = sum(r_size for _, _, _, r_size in sections)
        print('{}: {} sections totalling {}MB'.format(k, len(sections), total // (1024 * 1024)))

    rows = []
    with open(in_csv, 'r', encoding='utf-8') as fh:
        r = csv.DictReader(fh)
        for row in r:
            rows.append(row)
    print('Input RTTI entries: {}'.format(len(rows)))

    # For each mangled string, search each target .rdata for a unique match.
    stats = {k: 0 for k in BINARIES}
    out_rows = []
    for row in rows:
        mangled = row['mangled']
        needle = mangled.encode('ascii') + b'\0'
        out = {
            'mangled': mangled,
            'demangled': row.get('demangled', ''),
            'og_rtti_va': '0x' + row['og_rtti_string_address'],
            'ae_rtti_va': '0x' + row['ae_rtti_string_address'],
        }
        stats['og'] += 1
        stats['ae'] += 1
        for k in ('og', 'ng', 'ae', 'vr'):
            if k not in pe:
                continue
            if k in ('og', 'ae'):
                # already known from source CSV — count only if we can verify
                col_key = '{}_rtti_va'.format(k)
                if out.get(col_key):
                    continue
            image_base, sections, data = pe[k]
            p = data.find(needle)
            if p < 0:
                continue
            p2 = data.find(needle, p + 1)
            if p2 >= 0:
                continue
            va = file_off_to_va(p, image_base, sections)
            if va is None:
                continue
            out['{}_rtti_va'.format(k)] = '0x{:x}'.format(va)
            if k in ('ng', 'vr'):
                stats[k] += 1
        out_rows.append(out)

    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    with open(out_csv, 'w', newline='', encoding='utf-8') as fh:
        w = csv.DictWriter(fh, fieldnames=[
            'mangled', 'demangled',
            'og_rtti_va', 'ng_rtti_va', 'ae_rtti_va', 'vr_rtti_va'])
        w.writeheader()
        for r in out_rows:
            w.writerow(r)

    print('\nRTTI coverage per version:')
    for k, n in stats.items():
        print('  {}: {} / {} ({:.1f}%)'.format(
            k, n, len(rows), 100.0 * n / max(1, len(rows))))
    print('Wrote {} rows -> {}'.format(len(out_rows), out_csv))


if __name__ == '__main__':
    main()
