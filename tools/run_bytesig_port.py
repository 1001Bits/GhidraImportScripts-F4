"""One-shot byte-signature port driver.

Reads the generator's resolved symbol list (via parse_commonlibf4_types) plus
the external CSV sources (fo4_database, new_address_contributions), then
ports each resolved RVA into the other F4 binaries via byte-signature
matching.  Emits fallout4_bytesig_map.csv with columns (name,og,ng,ae,vr)
for consumption by the generator's cross-version pass.
"""
import os
import sys
import csv

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_THIS_DIR)
sys.path.insert(0, _THIS_DIR)
sys.path.insert(0, _PROJECT_DIR)

from bytesig_port import load_pe_text, build_prefix_index, port_symbols

IMAGE_BASE = 0x140000000

BINARIES = {
    'og': r'C:\Games\Fallout.4 1.10.163\Fallout4.exe',
    'ng': r'C:\Games\Steam\steamapps\content\app_377160\depot_377162\Fallout4.exe.unpacked.exe',
    'ae': r'C:\Games\Steam\steamapps\common\Fallout 4 AE\Fallout4.exe.unpacked.exe',
    'vr': r'C:\Games\Steam\steamapps\common\Fallout 4 VR\Fallout4VR.exe.unpacked.exe',
}

# Port pairs: (source_key, target_key, description).  Run most-productive pairs
# first and let the dedup pass in the generator handle multi-source overlaps.
PORT_PAIRS = [
    # Every F4 binary has a distinct PDB GUID — all four are independent builds,
    # so every pair is cross-build and the masked retry runs on all of them.
    ('ae', 'ng', 'CommonLibF4 AE -> NG'),
    ('ng', 'ae', 'CommonLibF4 NG -> AE'),
    ('og', 'ng', 'fo4_database OG -> NG (different build)'),
    ('og', 'ae', 'fo4_database OG -> AE (different build)'),
    ('vr', 'ng', 'fo4_database VR -> NG (different build)'),
    ('vr', 'ae', 'fo4_database VR -> AE (different build)'),
    ('og', 'vr', 'OG -> VR (cross-check existing og_to_vr CSV)'),
    ('ae', 'vr', 'AE -> VR'),
    ('ng', 'vr', 'NG -> VR'),
    ('ae', 'og', 'AE -> OG'),
    ('ng', 'og', 'NG -> OG'),
    ('vr', 'og', 'VR -> OG'),
]


def _collect_source_symbols():
    """Build {name: {og,ng,ae,vr}} from CommonLibF4 + fo4_database + HIGGS."""
    import parse_commonlibf4_types as gen

    print('Loading address DBs...')
    addr_lib = gen.AddressLibrary()
    addr_lib.load_all(os.path.join(_PROJECT_DIR, 'addresslibrary'))
    print('  OG:{} NG:{} AE:{} VR:{}'.format(
        len(addr_lib.f4og_db), len(addr_lib.f4ng_db),
        len(addr_lib.f4ae_db), len(addr_lib.f4vr_db)))

    # Parse CommonLibF4 headers to get the ID->name mapping.
    import clang.cindex as ci
    print('Parsing CommonLibF4 headers for ID->name map...')
    cfg = gen.VERSIONS['f4ae']
    parse_args = gen.PARSE_ARGS_BASE + cfg['defines']
    idx = ci.Index.create()
    tu = idx.parse(gen.FALLOUT_H, args=parse_args, options=gen.PARSE_OPTIONS_FULL)
    hdr_funcs, hdr_labels, id_map, static_methods = gen._collect_relocations_from_tu(tu)
    src_dir = os.path.join(_PROJECT_DIR, 'extern', 'CommonLibF4', 'src')
    if os.path.isdir(src_dir):
        src_funcs = gen._collect_src_relocations(src_dir, addr_lib, id_map=id_map)
    else:
        src_funcs = []
    seen_ids = set(fs['id'] for fs in hdr_funcs if fs.get('id'))
    merged = list(hdr_funcs)
    for fs in src_funcs:
        fid = fs.get('id')
        if fid and fid in seen_ids:
            continue
        if fid:
            seen_ids.add(fid)
        merged.append(fs)

    syms = {}
    for fs in merged:
        name = fs.get('name')
        cls = fs.get('class_')
        if not name:
            continue
        full = '{}::{}'.format(cls, name) if cls else name
        id_val = fs.get('id')
        if not id_val:
            continue
        entry = syms.setdefault(full, {})
        for vkey, db in (('ng', addr_lib.f4ng_db), ('ae', addr_lib.f4ae_db)):
            off = db.get(int(id_val))
            if off is not None:
                entry[vkey] = off
    for lbl in hdr_labels:
        name = lbl.get('name')
        id_val = lbl.get('id')
        if not name or not id_val:
            continue
        entry = syms.setdefault(name, {})
        for vkey, db in (('ng', addr_lib.f4ng_db), ('ae', addr_lib.f4ae_db)):
            off = db.get(int(id_val))
            if off is not None:
                entry[vkey] = off

    # External: fo4_database (OG + VR).
    db_path = os.path.normpath(os.path.join(
        _PROJECT_DIR, '..', '..', 'MasterModTemplate', 'Shared',
        'AddressLibraries', 'Fallout4', 'fo4_database.csv'))
    fo4db = gen._load_fo4_database(db_path)
    print('  fo4_database.csv (status>=3): {}'.format(len(fo4db)))
    for s in fo4db:
        entry = syms.setdefault(s['n'], {})
        for k in ('og', 'vr'):
            if k in s:
                entry.setdefault(k, s[k])

    higgs_path = os.path.normpath(os.path.join(
        _PROJECT_DIR, '..', '..', 'MasterModTemplate', 'Shared',
        'AddressLibraries', 'Fallout4', 'new_address_contributions_resolved.csv'))
    higgs = gen._load_new_address_contributions(higgs_path)
    print('  HIGGS contributions: {}'.format(len(higgs)))
    for s in higgs:
        entry = syms.setdefault(s['n'], {})
        for k in ('og', 'vr'):
            if k in s:
                entry.setdefault(k, s[k])

    # F4 OG and F4VR PDB public functions — large fallback pools.  Porting
    # these OG->AE/NG and VR->* via byte-sig extends AE/NG fallback coverage
    # by tens of thousands of names.
    shared = os.path.normpath(os.path.join(
        _PROJECT_DIR, '..', '..', 'MasterModTemplate', 'Shared', 'GhidraAnalysis'))
    og_pdb = gen._load_pdb_pub_functions(
        os.path.join(shared, 'F4VR_Exports', 'f4_pdb_pub_functions.txt'),
        'og', 'F4OG_PDB')
    print('  OG PDB pub functions: {}'.format(len(og_pdb)))
    for s in og_pdb:
        entry = syms.setdefault(s['n'], {})
        if 'og' in s:
            entry.setdefault('og', s['og'])
    vr_pdb = gen._load_pdb_pub_functions(
        os.path.join(shared, 'F4VR_Exports', 'f4vr_pdb_pub_functions.txt'),
        'vr', 'F4VR_PDB')
    print('  VR PDB pub functions: {}'.format(len(vr_pdb)))
    for s in vr_pdb:
        entry = syms.setdefault(s['n'], {})
        if 'vr' in s:
            entry.setdefault('vr', s['vr'])

    return syms


def main():
    out_csv = os.path.normpath(os.path.join(
        _PROJECT_DIR, '..', '..', 'MasterModTemplate', 'Shared',
        'GhidraAnalysis', 'CrossVersionMaps', 'fallout4_bytesig_map.csv'))

    syms = _collect_source_symbols()
    print('\nTotal candidate names: {}'.format(len(syms)))

    # Load PE .text sections once.
    pe = {}
    for k, path in BINARIES.items():
        if not os.path.isfile(path):
            print('  {}: MISSING {}'.format(k.upper(), path))
            continue
        image_base, text_rva, text = load_pe_text(path)
        print('  {}: image_base=0x{:x} text_rva=0x{:x} text={}MB'.format(
            k.upper(), image_base, text_rva, len(text) // (1024 * 1024)))
        pe[k] = (image_base, text_rva, text)

    # Build target prefix indexes once per target.
    target_idx = {}
    for k in set(t for _, t, _ in PORT_PAIRS):
        if k not in pe:
            continue
        print('Indexing {}.text...'.format(k.upper()))
        _, _, text = pe[k]
        target_idx[k] = build_prefix_index(text, k=6)
        print('  {} distinct 6-byte prefixes'.format(len(target_idx[k])))

    # Run each port pair, extending syms dict in place.  VR pairs get a second
    # masked pass (wildcarding rel32/rip-rel) since VR diverges enough from
    # OG/NG/AE that exact 32-byte windows almost never match.
    def _do_pair(src_k, tgt_k, label, masked=False):
        if src_k not in pe or tgt_k not in pe:
            return
        src_rvas = []
        for name, verset in syms.items():
            if src_k in verset and tgt_k not in verset:
                src_rvas.append((name, verset[src_k]))
        if not src_rvas:
            return
        _, s_text_rva, s_text = pe[src_k]
        _, t_text_rva, t_text = pe[tgt_k]
        ported, stats = port_symbols(
            src_rvas, s_text_rva, s_text,
            t_text_rva, t_text, target_idx[tgt_k], masked=masked,
            progress_every=(20000 if masked else 0))
        tag = ' [masked]' if masked else ''
        print('{}{}: {} candidates -> {} ported ({:.1f}%) [prefix_miss={} ambig/zero={} oob={}]'.format(
            label, tag, len(src_rvas), stats['ok'],
            100.0 * stats['ok'] / max(1, len(src_rvas)),
            stats['no_prefix'], stats['ambiguous_or_zero'], stats['missing_src']))
        for name, tgt_rva in ported:
            syms[name][tgt_k] = tgt_rva

    # Every F4 binary has a distinct PDB GUID — rip-rel / rel32 displacements
    # drift between all compiles, so the masked retry (which wildcards those
    # displacements) runs on every pair to catch whatever the exact-byte
    # window missed.
    CROSS_BUILD_PAIRS = set((s, t) for s, t, _ in PORT_PAIRS)
    for src_k, tgt_k, label in PORT_PAIRS:
        _do_pair(src_k, tgt_k, label, masked=False)
    for src_k, tgt_k, label in PORT_PAIRS:
        if (src_k, tgt_k) in CROSS_BUILD_PAIRS:
            _do_pair(src_k, tgt_k, label, masked=True)

    # Emit CSV — only rows that gained at least one new mapping.
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    with open(out_csv, 'w', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh)
        w.writerow(['name', 'og', 'ng', 'ae', 'vr'])
        emitted = 0
        for name, verset in sorted(syms.items()):
            if len(verset) < 2:
                continue
            row = [name]
            for k in ('og', 'ng', 'ae', 'vr'):
                row.append('0x{:x}'.format(verset[k]) if k in verset else '')
            w.writerow(row)
            emitted += 1
    print('\nWrote {} ({} symbols with >=2 version offsets)'.format(out_csv, emitted))


if __name__ == '__main__':
    main()
