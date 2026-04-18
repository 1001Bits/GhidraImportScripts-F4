# GhidraImportScripts-F4

Ghidra import scripts for Fallout 4 — generated from
[CommonLibF4](https://github.com/alandtse/CommonLibF4) headers.  The
generator parses the CommonLib headers with libclang, resolves each
`REL::ID(N)` / `RE::RTTI::*` / `RE::VTABLE::*` entry against the Fallout 4
address library binary, and emits a stand-alone Ghidra Jython script that
applies struct and enum types, function names, and RTTI/vtable labels to
an open Ghidra program.

This is a **port** of [doodlum/GhidraImportScripts](https://github.com/doodlum/GhidraImportScripts)
(the original targets CommonLibSSE for Skyrim SE/AE) to CommonLibF4.

## Status

- **F4 NG (1.10.980 – 1.11.191)**: fully supported — ~22,150 symbols emit
  (891 functions, 21,259 RTTI/vtable labels).
- **F4 OG (1.10.163)** and **F4 VR (1.2.72)**: scripts generate but are
  empty-of-symbols.  CommonLibF4 IDs live in the NG namespace, and the
  OG/VR address libraries use disjoint ID namespaces.  Adding real OG/VR
  coverage would need an external cross-version ID mapping table, which
  doesn't exist upstream.  Types and enums still apply on all three.

## Build

```bat
git clone --recurse-submodules https://github.com/1001Bits/GhidraImportScripts-F4
cd GhidraImportScripts-F4
pip install libclang
python parse_commonlibf4_types.py
```

Outputs land in `ghidrascripts/`:
- `CommonLibImport_F4NG.py`
- `CommonLibImport_F4OG.py`
- `CommonLibImport_F4VR.py`

## Address library files

The generator expects these under `addresslibrary/`:
- `version-1-10-163-0.bin` — F4 OG (1.10.163), V0 binary format
- `version-1-11-191-0.bin` — F4 NG (1.11.191), V0 binary format
- `version-1-2-72-0.csv` — F4 VR (1.2.72), CSV format

## Running in Ghidra

1. In CodeBrowser, open the Script Manager (`Window → Script Manager`).
2. Add `ghidrascripts/` to the bundle paths.
3. Select `CommonLibImport_F4NG.py` (or OG/VR) and run.  Apply to the
   corresponding Fallout4.exe binary.

## Credits

- Original generator design: [doodlum/GhidraImportScripts](https://github.com/doodlum/GhidraImportScripts)
  (fancierimport branch).
- CommonLibF4 headers: [alandtse/CommonLibF4](https://github.com/alandtse/CommonLibF4).
- Fallout 4 Address Library: [meh321](https://www.nexusmods.com/fallout4/mods/47327).
