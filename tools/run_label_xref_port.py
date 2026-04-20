"""Port cross-version label RVAs via function-internal rip-rel xrefs.

Data labels (vtables, static objects, strings) have no executable bytes of
their own, so byte-sig matching can't port them.  Instead we use the fact
that code *references* them via rip-rel `lea/mov` instructions, and those
reference sites sit *inside* functions whose RVAs we've already byte-sig
ported across versions.

Algorithm, per source version S ∈ {og, ng, ae, vr}:
  1. Build {rva_S -> name} for every label whose S-version RVA we know
     (fo4_database for og/vr; CommonLibF4 address libraries for ng/ae;
     both can contribute og and vr too).
  2. Index S's function starts: PDB functions for og/vr, bytesig_map
     cross-version anchors for ng/ae (which has no PDB).
  3. Disassemble each function; record rip-rel targets that hit a label RVA.
     Emit (label_name, fn_rva_S, insn_offset_within_fn, insn_size).
  4. For each target version T, look up fn_rva_T via bytesig_map.
     Disassemble the analogous T offset, confirm the instruction shape
     matches S's, and extract the new rip-rel target as the label's
     T-version RVA.
  5. Emit fallout4_label_xref_map.csv (name,og,ng,ae,vr).
"""
import os
import sys
import csv
import struct
import bisect

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_THIS_DIR)
sys.path.insert(0, _THIS_DIR)
sys.path.insert(0, _PROJECT_DIR)

import parse_commonlibf4_types as gen
from bytesig_port import load_pe_text

BINARIES = {
    'og': r'C:\Games\Fallout.4 1.10.163\Fallout4.exe',
    'ng': r'C:\Games\Steam\steamapps\content\app_377160\depot_377162\Fallout4.exe.unpacked.exe',
    'ae': r'C:\Games\Steam\steamapps\common\Fallout 4 AE\Fallout4.exe.unpacked.exe',
    'vr': r'C:\Games\Steam\steamapps\common\Fallout 4 VR\Fallout4VR.exe.unpacked.exe',
}


def _load_bytesig_func_map(path):
    """name -> {og,ng,ae,vr} for every row in fallout4_bytesig_map.csv."""
    out = {}
    with open(path, 'r', encoding='utf-8', newline='') as fh:
        r = csv.DictReader(fh)
        for row in r:
            name = (row.get('name') or '').strip()
            if not name:
                continue
            entry = {}
            for k in ('og', 'ng', 'ae', 'vr'):
                v = (row.get(k) or '').strip()
                if v:
                    try:
                        entry[k] = int(v, 16)
                    except ValueError:
                        pass
            if entry:
                out[name] = entry
    return out


def _load_labels_fo4db():
    """name -> {og_rva, vr_rva} for fo4_database 'label' entries."""
    db_path = os.path.normpath(os.path.join(
        _PROJECT_DIR, '..', '..', 'MasterModTemplate', 'Shared',
        'AddressLibraries', 'Fallout4', 'fo4_database.csv'))
    db = gen._load_fo4_database(db_path)
    labels = {}
    for s in db:
        if s.get('t') != 'label':
            continue
        entry = {k: s[k] for k in ('og', 'vr') if k in s}
        if entry:
            labels[s['n']] = entry
    return labels


def _load_labels_commonlibf4():
    """name -> {ng_rva, ae_rva} for CommonLibF4 hdr_labels via AE/NG address libs.

    These are the NiRTTI_* and other data labels that fo4_database doesn't have
    — they unlock AE -> NG porting for the 13K+ NiRTTI entries that AE's
    address library knows but NG's doesn't.
    """
    addr = gen.AddressLibrary()
    addr.load_all(os.path.join(_PROJECT_DIR, 'addresslibrary'))

    import clang.cindex as ci
    cfg = gen.VERSIONS['f4ae']
    parse_args = gen.PARSE_ARGS_BASE + cfg['defines']
    idx = ci.Index.create()
    tu = idx.parse(gen.FALLOUT_H, args=parse_args,
                   options=gen.PARSE_OPTIONS_FULL)
    _hdr_funcs, hdr_labels, _id_map, _static = gen._collect_relocations_from_tu(tu)

    labels = {}
    for lbl in hdr_labels:
        name = lbl.get('name')
        idv = lbl.get('id')
        if not name or not idv:
            continue
        i = int(idv)
        entry = {}
        for vkey, db in (('ng', addr.f4ng_db), ('ae', addr.f4ae_db)):
            off = db.get(i)
            if off is not None:
                entry[vkey] = off
        if entry:
            labels[name] = entry
    return labels


def _merge_label_sources(*sources):
    """Merge multiple {name: {k: rva}} dicts — earlier wins on conflict."""
    out = {}
    for src in sources:
        for name, entry in src.items():
            e = out.setdefault(name, {})
            for k, v in entry.items():
                e.setdefault(k, v)
    return out


def _load_pdb_functions_rvas(path, version_key):
    """Return sorted list of function RVAs in .text."""
    rvas = []
    with open(path, 'r', encoding='utf-8') as fh:
        for line in fh:
            line = line.rstrip('\n')
            if not line.startswith('seg1:'):
                continue
            bar = line.find('|')
            if bar == -1:
                continue
            try:
                off = int(line[5:bar], 16)
            except ValueError:
                continue
            rvas.append(off + gen.PE_TEXT_RVA)
    rvas = sorted(set(rvas))
    return rvas


def _enclosing_function(insn_rva, func_rvas_sorted):
    """Return function start RVA whose body contains insn_rva (simple binary search)."""
    i = bisect.bisect_right(func_rvas_sorted, insn_rva)
    if i == 0:
        return None
    return func_rvas_sorted[i - 1]


def _scan_xrefs(src_key, binaries, labels,
                func_rvas_sorted, max_fn_span=0x8000):
    """Scan S's .text for rip-rel xrefs targeting any label RVA.

    Returns list of (name, fn_rva, insn_offset_in_fn, insn_size).
    """
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    path = binaries[src_key]
    image_base, text_rva, text = load_pe_text(path)
    print('  {}: .text at rva=0x{:x}, {}MB'.format(
        src_key.upper(), text_rva, len(text) // (1024 * 1024)))

    # Build set of label RVAs → name for O(1) lookup.
    rva_to_name = {}
    for name, entry in labels.items():
        rva = entry.get(src_key)
        if rva is not None:
            rva_to_name[rva] = name
    print('    {} {}-rva labels to locate'.format(len(rva_to_name), src_key))

    found = []  # (name, fn_rva, offset, size)
    seen = set()  # dedup (name, fn_rva)
    processed = 0
    for fn_rva in func_rvas_sorted:
        # Bound function span: walk up to min(next_fn, max_fn_span).
        idx = bisect.bisect_right(func_rvas_sorted, fn_rva)
        if idx < len(func_rvas_sorted):
            span = min(func_rvas_sorted[idx] - fn_rva, max_fn_span)
        else:
            span = max_fn_span
        off = fn_rva - text_rva
        if off < 0 or off >= len(text):
            continue
        end = min(off + span, len(text))
        code = bytes(text[off:end])
        for ins in md.disasm(code, fn_rva):
            # Check for rip-rel mem operand.
            try:
                ops = ins.operands
            except Exception:
                continue
            for op in ops:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    tgt_rva = (ins.address + ins.size + op.mem.disp) - 0  # disp is signed; absolute since we passed fn_rva as base
                    name = rva_to_name.get(tgt_rva)
                    if name is None:
                        break
                    key = (name, fn_rva)
                    if key in seen:
                        break
                    seen.add(key)
                    found.append((name, fn_rva, ins.address - fn_rva, ins.size))
                    break
        processed += 1
        if processed % 20000 == 0:
            print('    scanned {}/{} functions, {} xrefs'.format(
                processed, len(func_rvas_sorted), len(found)))
    print('    done: {} xref sites for {} unique labels'.format(
        len(found), len(set(n for n, _, _, _ in found))))
    return found, text, text_rva


def _port_via_xrefs(xrefs, src_text, src_text_rva, src_key, bytesig_funcs,
                    labels, binaries, result):
    """For each xref site, try to propagate label to ng/ae/vr via bytesig match.

    Args:
      xrefs: list of (name, fn_rva, offset, size) in source version
      result: dict name -> {og,ng,ae,vr} — enriched in place
    """
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    # Build reverse index: source_fn_rva -> bytesig row (with cross-version RVAs).
    fn_by_src_rva = {}
    for name, vers in bytesig_funcs.items():
        rva_s = vers.get(src_key)
        if rva_s is None:
            continue
        fn_by_src_rva.setdefault(rva_s, vers)

    # Load target binaries lazily.
    tgt_text = {}
    for tkey in ('og', 'ng', 'ae', 'vr'):
        if tkey == src_key:
            continue
        if tkey not in binaries:
            continue
        path = binaries[tkey]
        if not os.path.isfile(path):
            continue
        _, t_rva, t_bytes = load_pe_text(path)
        tgt_text[tkey] = (t_rva, t_bytes)

    ported_per_target = {k: 0 for k in ('ng', 'ae', 'vr', 'og')}
    shape_mismatch = {k: 0 for k in ('ng', 'ae', 'vr', 'og')}
    no_fn_map = 0

    for name, fn_rva, offset, size in xrefs:
        fn_vers = fn_by_src_rva.get(fn_rva)
        if fn_vers is None:
            no_fn_map += 1
            continue
        # Source-version label RVA (already known).
        src_label_rva = labels[name].get(src_key)
        entry = result.setdefault(name, {})
        if src_label_rva is not None:
            entry.setdefault(src_key, src_label_rva)
        # Also preserve the other source-version RVA if present.
        for sk in ('og', 'vr'):
            if sk in labels[name]:
                entry.setdefault(sk, labels[name][sk])

        # For each target version, locate fn in target and read the instruction.
        for tkey in ('og', 'ng', 'ae', 'vr'):
            if tkey == src_key:
                continue
            if tkey in entry:
                continue  # already have this slot
            tgt_fn_rva = fn_vers.get(tkey)
            if tgt_fn_rva is None:
                continue
            if tkey not in tgt_text:
                continue
            t_text_rva, t_text = tgt_text[tkey]
            t_off = (tgt_fn_rva + offset) - t_text_rva
            if t_off < 0 or t_off + size > len(t_text):
                continue
            # Verify shape: decode one instruction, confirm size matches.
            code = bytes(t_text[t_off:t_off + size + 8])
            decoded = None
            for ins in md.disasm(code, tgt_fn_rva + offset):
                decoded = ins
                break
            if decoded is None or decoded.size != size:
                shape_mismatch[tkey] += 1
                continue
            # Confirm rip-rel mem operand, extract target RVA.
            try:
                ops = decoded.operands
            except Exception:
                continue
            tgt_rva = None
            for op in ops:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    tgt_rva = (decoded.address + decoded.size + op.mem.disp)
                    break
            if tgt_rva is None:
                shape_mismatch[tkey] += 1
                continue
            entry[tkey] = tgt_rva
            ported_per_target[tkey] += 1

    print('  Port stats from {}:'.format(src_key))
    for tkey in ('og', 'ng', 'ae', 'vr'):
        if tkey == src_key:
            continue
        print('    -> {}: {} ported, {} shape-mismatch'.format(
            tkey, ported_per_target[tkey], shape_mismatch[tkey]))
    print('    (no fn map: {} xref sites)'.format(no_fn_map))


def main():
    shared = os.path.normpath(os.path.join(
        _PROJECT_DIR, '..', '..', 'MasterModTemplate', 'Shared', 'GhidraAnalysis'))
    bytesig_csv = os.path.join(shared, 'CrossVersionMaps', 'fallout4_bytesig_map.csv')
    out_csv = os.path.join(shared, 'CrossVersionMaps', 'fallout4_label_xref_map.csv')

    print('Loading bytesig function map...')
    bytesig_funcs = _load_bytesig_func_map(bytesig_csv)
    print('  {} cross-version function anchors'.format(len(bytesig_funcs)))

    print('Loading fo4_database labels...')
    labels_fo4 = _load_labels_fo4db()
    print('  {} labels (og/vr)'.format(len(labels_fo4)))

    print('Loading CommonLibF4 hdr_labels...')
    labels_cl = _load_labels_commonlibf4()
    print('  {} labels (ng/ae)'.format(len(labels_cl)))

    labels = _merge_label_sources(labels_fo4, labels_cl)
    print('  Merged: {} unique labels'.format(len(labels)))

    og_pdb = os.path.join(shared, 'F4VR_Exports', 'f4_pdb_pub_functions.txt')
    vr_pdb = os.path.join(shared, 'F4VR_Exports', 'f4vr_pdb_pub_functions.txt')

    print('Loading OG PDB function RVAs...')
    og_fns = _load_pdb_functions_rvas(og_pdb, 'og')
    print('  {} OG PDB functions'.format(len(og_fns)))

    print('Loading VR PDB function RVAs...')
    vr_fns = _load_pdb_functions_rvas(vr_pdb, 'vr')
    print('  {} VR PDB functions'.format(len(vr_fns)))

    # NG and AE have no PDB — use bytesig_map anchors as synthetic function
    # starts.  Each row in bytesig_funcs that has an NG/AE RVA is a validated
    # cross-version function anchor, good enough to bound a scan region.
    ng_fns = sorted(set(v['ng'] for v in bytesig_funcs.values() if 'ng' in v))
    ae_fns = sorted(set(v['ae'] for v in bytesig_funcs.values() if 'ae' in v))
    print('  NG bytesig anchors (used as fn starts): {}'.format(len(ng_fns)))
    print('  AE bytesig anchors (used as fn starts): {}'.format(len(ae_fns)))

    result = {}

    print('\n=== Scanning OG for label xrefs ===')
    og_xrefs, _, _ = _scan_xrefs('og', BINARIES, labels, og_fns)
    print('\n  Porting OG -> NG/AE/VR...')
    _port_via_xrefs(og_xrefs, None, None, 'og', bytesig_funcs, labels, BINARIES, result)

    print('\n=== Scanning VR for label xrefs ===')
    vr_xrefs, _, _ = _scan_xrefs('vr', BINARIES, labels, vr_fns)
    print('\n  Porting VR -> NG/AE/OG...')
    _port_via_xrefs(vr_xrefs, None, None, 'vr', bytesig_funcs, labels, BINARIES, result)

    print('\n=== Scanning AE for label xrefs ===')
    ae_xrefs, _, _ = _scan_xrefs('ae', BINARIES, labels, ae_fns)
    print('\n  Porting AE -> NG/OG/VR...')
    _port_via_xrefs(ae_xrefs, None, None, 'ae', bytesig_funcs, labels, BINARIES, result)

    print('\n=== Scanning NG for label xrefs ===')
    ng_xrefs, _, _ = _scan_xrefs('ng', BINARIES, labels, ng_fns)
    print('\n  Porting NG -> AE/OG/VR...')
    _port_via_xrefs(ng_xrefs, None, None, 'ng', bytesig_funcs, labels, BINARIES, result)

    # Emit CSV.
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    with open(out_csv, 'w', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh)
        w.writerow(['name', 'og', 'ng', 'ae', 'vr'])
        emitted = 0
        for name in sorted(result.keys()):
            entry = result[name]
            if sum(1 for k in ('og', 'ng', 'ae', 'vr') if k in entry) < 2:
                continue
            row = [name]
            for k in ('og', 'ng', 'ae', 'vr'):
                row.append('0x{:x}'.format(entry[k]) if k in entry else '')
            w.writerow(row)
            emitted += 1
    print('\nWrote {} ({} labels with >=2 version offsets)'.format(out_csv, emitted))


if __name__ == '__main__':
    main()
