"""Walk MSVC x64 RTTI from known type descriptors to enumerate vftable slots.

Inputs:
  fallout4_rtti_all_versions.csv  — per-version VAs of each RTTI mangled string

For each (version, class) pair this tool:
  1. Resolves TypeDescriptor VA from the mangled-string VA (td = str - 0x10).
  2. Scans .rdata for CompleteObjectLocator entries pointing at that TD
     (uint32 RVA at COL+0x0C), validated via pSelf at COL+0x14.
  3. Scans .rdata for uint64 references to each COL VA — those sit at
     [vftable-8].
  4. Reads consecutive 8-byte function pointers from the vftable until
     a non-.text value is encountered.

Emits fallout4_vtable_slots.csv with columns:
  class, col_offset, slot, og, ng, ae, vr

`col_offset` is the COL's "offset of this base within complete object" field;
it's 0 for the primary COL (vftable owned by the class itself) and non-zero
for multiple-inheritance secondary bases.  Non-primary slots are emitted
under the name '<Class>::base_at_<offset>::slot_N' rather than '<Class>::slot_N'.
"""
import os
import sys
import csv
import struct

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_THIS_DIR)

IMAGE_BASE = 0x140000000

BINARIES = {
    'og': r'C:\Games\Fallout.4 1.10.163\Fallout4.exe',
    'ng': r'C:\Games\Steam\steamapps\content\app_377160\depot_377162\Fallout4.exe.unpacked.exe',
    'ae': r'C:\Games\Steam\steamapps\common\Fallout 4 AE\Fallout4.exe.unpacked.exe',
    'vr': r'C:\Games\Steam\steamapps\common\Fallout 4 VR\Fallout4VR.exe.unpacked.exe',
}


def load_pe(path):
    """Return (image_base, sections[(name, v_rva, v_size, r_off, r_size)], data)."""
    with open(path, 'rb') as fh:
        data = fh.read()
    pe_off = struct.unpack_from('<I', data, 0x3c)[0]
    is_pe32p = (struct.unpack_from('<H', data, pe_off + 0x18)[0] == 0x20b)
    if is_pe32p:
        image_base = struct.unpack_from('<Q', data, pe_off + 0x18 + 0x18)[0]
    else:
        image_base = struct.unpack_from('<I', data, pe_off + 0x18 + 0x1c)[0]
    nsec = struct.unpack_from('<H', data, pe_off + 6)[0]
    sec_off = pe_off + 0x18 + (0xf0 if is_pe32p else 0xe0)
    secs = []
    for i in range(nsec):
        s = sec_off + i * 0x28
        name = data[s:s + 8].rstrip(b'\0').decode('ascii', errors='replace')
        v_size = struct.unpack_from('<I', data, s + 8)[0]
        v_rva = struct.unpack_from('<I', data, s + 12)[0]
        r_size = struct.unpack_from('<I', data, s + 16)[0]
        r_off = struct.unpack_from('<I', data, s + 20)[0]
        secs.append((name, v_rva, v_size, r_off, r_size))
    return image_base, secs, data


def _section_for_va(va, image_base, secs):
    rva = va - image_base
    for name, v_rva, v_size, r_off, r_size in secs:
        if v_rva <= rva < v_rva + v_size:
            return name, v_rva, v_size, r_off, r_size
    return None


def _read_va(data, file_off):
    if file_off < 0 or file_off + 8 > len(data):
        return None
    return struct.unpack_from('<Q', data, file_off)[0]


def _read_rva(data, file_off):
    if file_off < 0 or file_off + 4 > len(data):
        return None
    return struct.unpack_from('<I', data, file_off)[0]


def _file_off_for_va(va, image_base, secs):
    info = _section_for_va(va, image_base, secs)
    if not info:
        return None
    name, v_rva, v_size, r_off, r_size = info
    rva = va - image_base
    return r_off + (rva - v_rva)


def _iter_rdata_bytes(image_base, secs, data):
    """Yield (section_file_off, section_file_end, section_v_rva) for each read-only data section."""
    for name, v_rva, v_size, r_off, r_size in secs:
        if name in ('.rdata', '.data'):
            yield name, r_off, r_off + r_size, v_rva


def build_td_index(image_base, secs, data):
    """Scan .rdata/.data for all (td_rva -> [col_rva]) bindings.

    For each uint32 in .rdata that could be a TD RVA, check whether reading it
    as an RVA yields bytes matching the TypeDescriptor signature (the first
    qword of a TypeDescriptor is the type_info vftable pointer — same for all
    TDs in the image).  But we don't know that vftable pointer up-front; we'll
    just validate against the known set of TD RVAs passed in.
    """
    raise NotImplementedError  # placeholder; we use find_cols_for_td instead


def find_cols_for_td(td_rva, image_base, secs, data, col_candidates):
    """Return list of COL RVAs whose pTypeDescriptor field equals td_rva.

    `col_candidates` is a prebuilt list/set of (position_rva, position_file_off)
    for every uint32 equal to a known TD RVA, keyed by td_rva.  For each
    candidate position, COL starts at position-0x0C and is validated via pSelf.
    """
    cols = []
    for pos_file_off, pos_rva in col_candidates.get(td_rva, ()):
        col_rva = pos_rva - 0x0C
        col_file_off = pos_file_off - 0x0C
        if col_file_off < 0:
            continue
        # Validate pSelf at COL+0x14 == col_rva.
        pself = _read_rva(data, col_file_off + 0x14)
        if pself != col_rva:
            continue
        # Signature at COL+0x00 must be 0 or 1.
        sig = _read_rva(data, col_file_off + 0x00)
        if sig not in (0, 1):
            continue
        cols.append(col_rva)
    return cols


def build_col_candidate_index(image_base, secs, data, td_rvas):
    """Scan .rdata/.data for uint32 values in td_rvas; return dict td_rva -> [(file_off, rva), ...]."""
    td_set = set(td_rvas)
    out = {}
    for sec_name, r_off, r_end, v_rva in _iter_rdata_bytes(image_base, secs, data):
        # Scan 4-byte-aligned positions.
        i = r_off
        # Align to 4.
        if i & 3:
            i = (i + 3) & ~3
        while i + 4 <= r_end:
            v = struct.unpack_from('<I', data, i)[0]
            if v in td_set:
                pos_rva = v_rva + (i - r_off)
                out.setdefault(v, []).append((i, pos_rva))
            i += 4
    return out


def build_qword_index(image_base, secs, data):
    """Return dict qword_value -> list[(file_off, va)] for all 8-byte-aligned
    positions in .rdata/.data.  Used to resolve COL VA → vftable VA in O(1).
    """
    idx = {}
    for sec_name, r_off, r_end, v_rva in _iter_rdata_bytes(image_base, secs, data):
        i = r_off
        if i & 7:
            i = (i + 7) & ~7
        while i + 8 <= r_end:
            v = struct.unpack_from('<Q', data, i)[0]
            if v:
                va = image_base + v_rva + (i - r_off)
                idx.setdefault(v, []).append((i, va))
            i += 8
    return idx


def find_vftables_for_col(col_rva, image_base, qword_idx):
    """Return list of vftable VAs whose [-8] slot points at COL VA."""
    col_va = image_base + col_rva
    out = []
    for _, pos_va in qword_idx.get(col_va, ()):
        out.append(pos_va + 8)
    return out


def walk_vftable_slots(vftable_va, image_base, secs, data, text_rva_range, max_slots=512):
    """Return list of function VAs in the vftable.

    Walks consecutive qwords until a non-.text pointer is encountered.
    """
    text_lo, text_hi = text_rva_range
    slots = []
    f_off = _file_off_for_va(vftable_va, image_base, secs)
    if f_off is None:
        return slots
    for k in range(max_slots):
        qw = _read_va(data, f_off + k * 8)
        if qw is None or qw == 0:
            break
        rva = qw - image_base
        if not (text_lo <= rva < text_hi):
            break
        slots.append(qw)
    return slots


def _text_range(image_base, secs):
    for name, v_rva, v_size, r_off, r_size in secs:
        if name == '.text':
            return v_rva, v_rva + v_size
    return 0, 0


def _demangled_to_class(demangled):
    """Strip '??_7<X>@@6B@' wrappers and '$' prefixes/suffixes.

    The CSV's 'demangled' field isn't the fully-undecorated class name but the
    RTTI name starting with `?`.  For our purposes we just normalize by
    stripping a few common decorators.  A richer demangler (UnDecorateSymbolName)
    is available in the generator but we keep this tool standalone.
    """
    return demangled


def main():
    in_csv = os.path.normpath(os.path.join(
        _PROJECT_DIR, '..', '..', 'MasterModTemplate', 'Shared',
        'GhidraAnalysis', 'CrossVersionMaps', 'fallout4_rtti_all_versions.csv'))
    out_csv = os.path.normpath(os.path.join(
        _PROJECT_DIR, '..', '..', 'MasterModTemplate', 'Shared',
        'GhidraAnalysis', 'CrossVersionMaps', 'fallout4_vtable_slots.csv'))

    # Parse RTTI CSV.
    rows = []
    with open(in_csv, 'r', encoding='utf-8') as fh:
        r = csv.DictReader(fh)
        for row in r:
            rows.append(row)
    print('RTTI rows: {}'.format(len(rows)))

    # Load all PEs and precompute text range.
    pe = {}
    for k, path in BINARIES.items():
        if not os.path.isfile(path):
            print('  {}: MISSING'.format(k))
            continue
        image_base, secs, data = load_pe(path)
        pe[k] = (image_base, secs, data, _text_range(image_base, secs))
        print('  {}: {} sections, .text={}..{}'.format(
            k, len(secs), hex(pe[k][3][0]), hex(pe[k][3][1])))

    # Per-version: td_rvas for each class, then COL candidates, then vftable walks.
    result = {}  # (class_mangled, col_offset, slot_idx) -> {og, ng, ae, vr}
    for vkey in ('og', 'ng', 'ae', 'vr'):
        if vkey not in pe:
            continue
        print('\n=== {} ==='.format(vkey.upper()))
        image_base, secs, data, text_range = pe[vkey]
        col_ix = '{}_rtti_va'.format(vkey)
        td_rvas = {}  # td_rva -> class mangled name
        for row in rows:
            va_s = (row.get(col_ix) or '').strip()
            if not va_s:
                continue
            try:
                str_va = int(va_s, 16)
            except ValueError:
                continue
            td_va = str_va - 0x10
            td_rva = td_va - image_base
            td_rvas[td_rva] = row['mangled']
        print('  TDs with {} VA: {}'.format(vkey, len(td_rvas)))

        print('  Building COL candidate index...')
        cand = build_col_candidate_index(image_base, secs, data, td_rvas.keys())
        print('    {} TD refs found in .rdata/.data'.format(sum(len(v) for v in cand.values())))

        print('  Building qword index...')
        qword_idx = build_qword_index(image_base, secs, data)
        print('    {} distinct qword values indexed'.format(len(qword_idx)))

        vftable_count = 0
        slot_count = 0
        for td_rva, mangled in td_rvas.items():
            cols = find_cols_for_td(td_rva, image_base, secs, data, cand)
            for col_rva in cols:
                col_file_off = _file_off_for_va(image_base + col_rva, image_base, secs)
                col_offset = _read_rva(data, col_file_off + 0x04)
                for vft_va in find_vftables_for_col(col_rva, image_base, qword_idx):
                    vftable_count += 1
                    slots = walk_vftable_slots(vft_va, image_base, secs, data, text_range)
                    for idx, fn_va in enumerate(slots):
                        key = (mangled, col_offset, idx)
                        entry = result.setdefault(key, {})
                        entry[vkey] = fn_va - image_base
                        slot_count += 1
        print('  {} vftables -> {} slot entries'.format(vftable_count, slot_count))

    # Emit CSV.
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    with open(out_csv, 'w', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh)
        w.writerow(['class_mangled', 'col_offset', 'slot', 'og', 'ng', 'ae', 'vr'])
        emitted = 0
        for (mangled, col_offset, slot), verset in sorted(result.items()):
            row = [mangled, col_offset, slot]
            for k in ('og', 'ng', 'ae', 'vr'):
                row.append('0x{:x}'.format(verset[k]) if k in verset else '')
            w.writerow(row)
            emitted += 1
    print('\nWrote {} slot entries to {}'.format(emitted, out_csv))


if __name__ == '__main__':
    main()
