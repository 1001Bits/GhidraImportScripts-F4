"""Cross-version name port via vtable slot structure.

Consumes fallout4_vtable_slots.csv (per-version RVAs for every MSVC x64 vftable
slot across 4 binaries).  For each slot we already know the RVA in all four
versions — structurally, by walking RTTI + following COL back-pointers.  We
just need a *name* for each slot, which we borrow from the OG and VR PDB
public-function lists by reverse-lookup.

Output fallout4_vtable_map.csv (name,og,ng,ae,vr) is consumed by the generator
exactly like fallout4_bytesig_map.csv — as extra version-slot enrichment for
existing symbols, or as standalone label entries.
"""
import os
import sys
import csv

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_THIS_DIR)
sys.path.insert(0, _PROJECT_DIR)

import parse_commonlibf4_types as gen


def _load_rva_to_name(path, version_key):
    """Parse PDB pub-function list; return {rva_int: name}."""
    out = {}
    entries = gen._load_pdb_pub_functions(path, version_key, 'VTablePort')
    for e in entries:
        rva = e.get(version_key)
        if rva is None:
            continue
        out.setdefault(rva, e['n'])
    return out


def _emit_typeinfo_labels(shared):
    """Emit ??_R0<class>@@8 labels from fallout4_rtti_all_versions.csv.

    TypeDescriptor sits at (RTTI-string VA - 0x10) — the string VA is what the
    CSV records per version.  MSVC-mangled name follows MSVC convention:
    `??_R0` + (class_mangled without the leading `.`) + `8`.  E.g.
    class_mangled=".?AVBGSActor@@" → "??_R0?AVBGSActor@@8".
    """
    rtti_csv = os.path.join(shared, 'CrossVersionMaps', 'fallout4_rtti_all_versions.csv')
    rows = []
    with open(rtti_csv, 'r', encoding='utf-8') as fh:
        r = csv.DictReader(fh)
        for row in r:
            cm = (row.get('mangled') or '').strip()
            if not cm.startswith('.') or not cm.endswith('@@'):
                continue
            name = '??_R0' + cm[1:] + '8'
            entry = {'name': name}
            any_ver = False
            for v in ('og', 'ng', 'ae', 'vr'):
                va_s = (row.get('{}_rtti_va'.format(v)) or '').strip()
                if not va_s:
                    continue
                try:
                    str_va = int(va_s, 16)
                except ValueError:
                    continue
                # TD RVA = (str_va - 0x10) - image_base.  Image base is
                # 0x140000000 for every Fallout 4 binary.
                td_va = str_va - 0x10
                entry[v] = td_va - 0x140000000
                any_ver = True
            if any_ver:
                rows.append(entry)
    return rows


def main():
    shared = os.path.normpath(os.path.join(
        _PROJECT_DIR, '..', '..', 'MasterModTemplate', 'Shared', 'GhidraAnalysis'))
    slots_csv = os.path.join(shared, 'CrossVersionMaps', 'fallout4_vtable_slots.csv')
    out_csv = os.path.join(shared, 'CrossVersionMaps', 'fallout4_vtable_map.csv')

    og_pdb_path = os.path.join(shared, 'F4VR_Exports', 'f4_pdb_pub_functions.txt')
    vr_pdb_path = os.path.join(shared, 'F4VR_Exports', 'f4vr_pdb_pub_functions.txt')

    print('Loading PDB reverse indexes...')
    og_idx = _load_rva_to_name(og_pdb_path, 'og')
    vr_idx = _load_rva_to_name(vr_pdb_path, 'vr')
    print('  OG rva->name: {}'.format(len(og_idx)))
    print('  VR rva->name: {}'.format(len(vr_idx)))

    # Secondary source: fo4_database gives OG and VR names too.
    db_path = os.path.normpath(os.path.join(
        _PROJECT_DIR, '..', '..', 'MasterModTemplate', 'Shared',
        'AddressLibraries', 'Fallout4', 'fo4_database.csv'))
    fo4db = gen._load_fo4_database(db_path)
    for s in fo4db:
        if s['t'] != 'func':
            continue
        if 'og' in s:
            og_idx.setdefault(s['og'], s['n'])
        if 'vr' in s:
            vr_idx.setdefault(s['vr'], s['n'])
    print('  +fo4_database merged; OG={}, VR={}'.format(len(og_idx), len(vr_idx)))

    print('Loading slots CSV...')
    slots = []
    with open(slots_csv, 'r', encoding='utf-8') as fh:
        r = csv.DictReader(fh)
        for row in r:
            try:
                col_offset = int(row['col_offset'])
                slot = int(row['slot'])
            except (ValueError, KeyError):
                continue
            entry = {
                'class': row['class_mangled'],
                'col_offset': col_offset,
                'slot': slot,
            }
            for k in ('og', 'ng', 'ae', 'vr'):
                v = (row.get(k) or '').strip()
                if v:
                    try:
                        entry[k] = int(v, 16)
                    except ValueError:
                        pass
            slots.append(entry)
    print('  {} slot rows'.format(len(slots)))

    # Resolve a name for each slot, then emit rows.  Prefer OG match first
    # (OG PDB pool is much larger than VR PDB pool), then VR fallback.
    resolved = []
    unresolved = 0
    name_counts = {}  # collision bookkeeping
    for s in slots:
        name = None
        if 'og' in s:
            name = og_idx.get(s['og'])
        if name is None and 'vr' in s:
            name = vr_idx.get(s['vr'])
        if name is None:
            unresolved += 1
            continue
        name_counts[name] = name_counts.get(name, 0) + 1
        resolved.append((name, s))

    print('  Resolved: {} / {} slots'.format(len(resolved), len(slots)))
    print('  Unresolved: {} slots'.format(unresolved))

    # Vtable label emission: for every primary vftable (col_offset == 0 and
    # slot == 0), the slot's per-version RVAs *are* the vftable's per-version
    # RVAs.  Emit as MSVC mangled label  ??_7<class>@@6B@.  Skip secondary
    # base vftables (col_offset != 0) — their mangling is more complex
    # (??_7<class>@@6B<base>@@@) and we don't have full inheritance info.
    vtable_labels = 0
    for s in slots:
        if s['col_offset'] != 0 or s['slot'] != 0:
            continue
        cm = s['class']
        # .?AV<class>@@ or .?AU<class>@@  →  ??_7<class>@@6B@
        if not cm.startswith('.?A') or len(cm) < 6 or not cm.endswith('@@'):
            continue
        # cm[3] is 'V' (class) or 'U' (struct); cm[4:-2] is the name body.
        if cm[3] not in ('V', 'U'):
            continue
        vt_name = '??_7' + cm[4:-2] + '@@6B@'
        resolved.append((vt_name, s))
        vtable_labels += 1
    print('  Vtable label rows: {}'.format(vtable_labels))

    # Emit — dedupe by (name, per-version tuple).  A name may appear in
    # multiple class slots (inherited methods, covariant overrides) but
    # should still point to the same RVA; if not we skip the conflict.
    accepted = {}  # name -> {og, ng, ae, vr}
    conflicts = 0
    for name, s in resolved:
        entry = accepted.get(name)
        if entry is None:
            entry = {k: s[k] for k in ('og', 'ng', 'ae', 'vr') if k in s}
            accepted[name] = entry
        else:
            bad = False
            for k in ('og', 'ng', 'ae', 'vr'):
                if k in s and k in entry and entry[k] != s[k]:
                    bad = True
                    break
            if bad:
                conflicts += 1
                continue
            for k in ('og', 'ng', 'ae', 'vr'):
                if k in s and k not in entry:
                    entry[k] = s[k]

    print('  Unique names: {} (dropped {} RVA-conflicts)'.format(
        len(accepted), conflicts))

    # RTTI typeinfo labels — one per class, structural from RTTI CSV.
    ti_rows = _emit_typeinfo_labels(shared)
    ti_added = 0
    for e in ti_rows:
        nm = e['name']
        ent = accepted.get(nm)
        if ent is None:
            accepted[nm] = {k: e[k] for k in ('og', 'ng', 'ae', 'vr') if k in e}
            ti_added += 1
        else:
            for k in ('og', 'ng', 'ae', 'vr'):
                if k in e:
                    ent.setdefault(k, e[k])
    print('  Typeinfo (??_R0) labels added: {}'.format(ti_added))

    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    with open(out_csv, 'w', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh)
        w.writerow(['name', 'og', 'ng', 'ae', 'vr'])
        emitted = 0
        for name in sorted(accepted.keys()):
            entry = accepted[name]
            if sum(1 for k in ('og', 'ng', 'ae', 'vr') if k in entry) < 2:
                continue
            row = [name]
            for k in ('og', 'ng', 'ae', 'vr'):
                row.append('0x{:x}'.format(entry[k]) if k in entry else '')
            w.writerow(row)
            emitted += 1
    print('\nWrote {} ({} symbols with >=2 version offsets)'.format(out_csv, emitted))


if __name__ == '__main__':
    main()
