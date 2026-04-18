# GhidraImportScripts-F4

Ghidra import scripts for Fallout 4 — generated from
[CommonLibF4](https://github.com/alandtse/CommonLibF4) headers.  The
generator parses the CommonLib headers with libclang, resolves each
`REL::ID(N)` / `RE::RTTI::*` / `RE::VTABLE::*` entry against the Fallout 4
address library, and emits a stand-alone Ghidra Jython script that applies
struct and enum types, function names, and RTTI/vtable labels to an open
Ghidra program.

This is a **port** of [doodlum/GhidraImportScripts](https://github.com/doodlum/GhidraImportScripts)
(the original targets CommonLibSSE for Skyrim SE/AE) to CommonLibF4.

## Status

| Version | Binary | Symbols resolved |
| --- | --- | --- |
| **F4 AE** (1.11.191) | `version-1-11-191-0.bin` | 22,150 (all symbols) |
| **F4 NG** (1.10.984) | `offsets-1-10-984-0.csv` | 9,065 (partial — shared ID space with AE but ~59% overlap) |
| F4 OG (1.10.163) | `version-1-10-163-0.bin` | 0 (disjoint ID namespace) |
| F4 VR (1.2.72) | `version-1-2-72-0.csv` | 0 (disjoint ID namespace) |

CommonLibF4 IDs live in the NG/AE namespace — OG and VR use separate,
disjoint address-library namespaces.  OG and VR scripts are still emitted
for structure / enum / type application, but the symbol list is empty.
Full OG/VR symbol coverage would require an external cross-version ID
mapping table that doesn't exist upstream.

## Build

```bat
git clone --recurse-submodules https://github.com/1001Bits/GhidraImportScripts-F4
cd GhidraImportScripts-F4
pip install libclang
python parse_commonlibf4_types.py
```

Outputs land in `ghidrascripts/`:
- `CommonLibImport_F4AE.py` (primary)
- `CommonLibImport_F4NG.py`
- `CommonLibImport_F4OG.py`
- `CommonLibImport_F4VR.py`

## Address library files

The generator expects these under `addresslibrary/`:
- `version-1-10-163-0.bin` — F4 OG (1.10.163), V0 binary format
- `offsets-1-10-984-0.csv` — F4 NG (1.10.984), CSV
- `version-1-11-191-0.bin` — F4 AE (1.11.191), V0 binary format
- `version-1-2-72-0.csv` — F4 VR (1.2.72), CSV with metadata row

## Running in Ghidra

1. In CodeBrowser, open the Script Manager (`Window → Script Manager`).
2. Add `ghidrascripts/` to the bundle paths.
3. Select the script matching your Fallout4.exe version and run.  Apply
   to the target binary.

## Credits

- Original generator design: [doodlum/GhidraImportScripts](https://github.com/doodlum/GhidraImportScripts)
  (fancierimport branch).
- CommonLibF4 headers: [alandtse/CommonLibF4](https://github.com/alandtse/CommonLibF4).
- Fallout 4 Address Library: [meh321](https://www.nexusmods.com/fallout4/mods/47327).
