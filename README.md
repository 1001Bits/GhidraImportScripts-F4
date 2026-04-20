# GhidraImportScripts-F4

Ghidra import scripts for Fallout 4 — generated from
[CommonLibF4](https://github.com/alandtse/CommonLibF4) headers, the public
address-library DBs, Microsoft PDBs, and a cross-version byte-signature /
xref porting pipeline.  One Ghidra Python script per F4 build.  Run it
against the matching binary and you get tens of thousands of labeled
functions, typed signatures, struct layouts, and named vtable methods —
no manual naming required.

This is a **port** of [doodlum/GhidraImportScripts](https://github.com/doodlum/GhidraImportScripts)
(originally targets CommonLibSSE for Skyrim SE/AE) to CommonLibF4.

## Grab the scripts

Pre-built scripts for every F4 version are attached to the latest
[Release](https://github.com/1001Bits/GhidraImportScripts-F4/releases).
No build step — drop the `.py` into a Ghidra script directory and run.

## Coverage

| Version | Exe | Primary symbols | Fallback symbols | Total |
| --- | --- | ---: | ---: | ---: |
| **F4 OG** (1.10.163) | `Fallout4.exe` | 107,703 | 180,468 | **288,171** |
| **F4 NG** (1.10.984) | `Fallout4.exe` | 51,830 | 6,561 | 58,391 |
| **F4 AE** (1.11.191) | `Fallout4.exe` | 65,248 | 6,221 | 71,469 |
| **F4 VR** (1.2.72) | `Fallout4VR.exe` | 104,517 | 62,648 | **167,165** |

Every script also applies 415 enums, 2,910 structs, and 295 vtables with
typed function-pointer slots under `/CommonLibF4/` in the DTM.

**Primary symbols** come from CommonLibF4 `REL::ID()` annotations, RTTI and
VTABLE tables, and status≥3 entries from the community address database.
**Fallback symbols** come from F4OG + F4VR Microsoft PDB public functions
and the Heisenberg contributions CSV.  Cross-version coverage is extended by a
byte-signature porting pass (wildcards rel32 / rip-rel displacements) and
a label-xref porting pass using the call graph.

## Version guard

Each script picks 6 well-spaced functions at generation time and records
32 bytes from each.  At runtime it reads the same windows from the open
binary and refuses to run on mismatch — you cannot accidentally apply the
wrong version's script.

## Running in Ghidra

1. Open your Fallout 4 binary in Ghidra (11.x+).  Let auto-analysis
   finish first.
2. `Window → Script Manager → Manage Script Directories` → add the folder
   containing the script you downloaded.
3. In Script Manager, select the script matching your exe version and
   click **Run** (green arrow).  First run takes 2–5 minutes.  Progress
   is printed to the console.

## Build from source

Only needed if you want to pull in newer CommonLibF4 headers or extend
the pipeline.

```bat
git clone --recurse-submodules https://github.com/1001Bits/GhidraImportScripts-F4
cd GhidraImportScripts-F4
pip install libclang
python parse_commonlibf4_types.py
```

Outputs land in `ghidrascripts/`.

### Address library files

The generator expects these under `addresslibrary/`:
- `version-1-10-163-0.bin` — F4 OG, V0 binary format
- `offsets-1-10-984-0.csv` — F4 NG, CSV
- `version-1-11-191-0.bin` — F4 AE, V0 binary format
- `version-1-2-72-0.csv` — F4 VR, CSV with metadata row

### Optional inputs (for fallback-symbol coverage)

- `Shared/AddressLibraries/Fallout4/fo4_database.csv` — community name
  database for OG + VR
- `Shared/AddressLibraries/Fallout4/new_address_contributions_resolved.csv`
  — Heisenberg contributions
- `Shared/GhidraAnalysis/F4VR_Exports/f4_pdb_pub_functions.txt` — OG PDB
  public functions (~187k names)
- `Shared/GhidraAnalysis/F4VR_Exports/f4vr_pdb_pub_functions.txt` — VR
  PDB public functions (~189k names)
- Paths to the four F4 binaries themselves, for byte-signature porting
  and version-guard canary bytes (edit the `BINARIES` and `VERSIONS` dicts
  if yours differ)
