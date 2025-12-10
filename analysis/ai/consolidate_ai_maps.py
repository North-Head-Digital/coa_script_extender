"""
consolidate_ai_maps.py

Utility to merge AI hunter outputs into unified hook/function maps.

Inputs (same folder):
  - coa_ai_hook_points.txt        (original AIBehaviorHunter)
  - coa_ai_extended_hooks.txt     (AIBehaviorHunter2)
  - coa_ai_functions.txt          (original detailed listings)
  - coa_ai_extended.txt           (AIBehaviorHunter2 detailed listings)

Outputs:
  - coa_ai_master_hooks.txt       (merged hooks, deduped, sorted by offset)
  - coa_ai_master_functions.txt   (merged functions, deduped, sorted by address)

Run:
  python consolidate_ai_maps.py

Notes:
  - Offsets are normalized as hex strings starting with 0x.
  - If the same name appears with different offsets, both are kept with a suffix.
  - If the same offset maps to multiple names, all names are preserved.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).parent


# ---------- Parsing helpers ----------

HOOK_LINE_RE = re.compile(r"^\s*([^#=]+?)\s*=\s*(0x[0-9a-fA-F]+)\s*$")
FUNCTION_ARROW_RE = re.compile(r"->\s+([^@]+?)\s*@\s*([0-9a-fA-Fx]+)")
FUNCTION_EQUALS_RE = re.compile(r"^\s*([0-9a-fA-Fx]+)\s*=\s*(\S+)\s*$")


def normalize_offset(addr: str) -> str:
    """Normalize addresses to 0x style hex offsets."""
    addr = addr.strip()
    if addr.startswith("0x"):
        return addr.lower()
    # Addresses like 1400abcd0 -> convert to offset 0x0abcd0
    if addr.startswith("140"):
        return "0x0" + addr[3:]
    if addr.startswith("14"):
        return "0x" + addr[2:]
    # Fallback: ensure 0x prefix
    if re.match(r"^[0-9a-fA-F]+$", addr):
        return "0x" + addr.lower()
    return addr.lower()


def parse_hook_file(path: Path) -> dict[str, str]:
    """Parse hook files of form `Name = 0xOFFSET`."""
    hooks: dict[str, str] = {}
    for line in path.read_text().splitlines():
        m = HOOK_LINE_RE.match(line)
        if not m:
            continue
        name, offset = m.groups()
        name = name.strip()
        hooks[name] = normalize_offset(offset)
    return hooks


def parse_functions_file(path: Path) -> dict[str, str]:
    """Parse function listings with either arrow or equals formats."""
    funcs: dict[str, str] = {}
    for line in path.read_text().splitlines():
        m1 = FUNCTION_ARROW_RE.search(line)
        if m1:
            name, addr = m1.groups()
            funcs[name.strip()] = normalize_offset(addr)
            continue
        m2 = FUNCTION_EQUALS_RE.match(line)
        if m2:
            addr, name = m2.groups()
            funcs[name.strip()] = normalize_offset(addr)
    return funcs


# ---------- Consolidation ----------

def merge_hooks(*hook_maps: dict[str, str]) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Merge hook dictionaries. Returns (name->offset, offset->names)."""
    name_to_offset: dict[str, str] = {}
    offset_to_names: defaultdict[str, list[str]] = defaultdict(list)

    for hmap in hook_maps:
        for name, off in hmap.items():
            # Handle name collision with differing offsets by suffixing
            if name in name_to_offset and name_to_offset[name] != off:
                alt_name = f"{name}__dup_{off}"  # keep both variants
                name_to_offset[alt_name] = off
                offset_to_names[off].append(alt_name)
                continue

            name_to_offset[name] = off
            offset_to_names[off].append(name)

    return name_to_offset, offset_to_names


def merge_functions(*func_maps: dict[str, str]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for fmap in func_maps:
        for name, off in fmap.items():
            # Prefer first occurrence; if differing offsets, suffix and keep both
            if name in merged and merged[name] != off:
                merged[f"{name}__dup_{off}"] = off
            else:
                merged[name] = off
    return merged


def write_hooks(path: Path, name_to_offset: dict[str, str], offset_to_names: dict[str, list[str]]):
    lines = [
        "# Master AI Hook Points",
        "# Merged from original and extended hunts",
        "# Format: FunctionName = 0xOFFSET",
        "",
    ]

    # Sort by numeric offset
    def off_key(off: str) -> int:
        try:
            return int(off, 16)
        except ValueError:
            return 0

    for off in sorted(offset_to_names.keys(), key=off_key):
        for name in sorted(offset_to_names[off]):
            lines.append(f"{name} = {off}")

    path.write_text("\n".join(lines))


def write_functions(path: Path, func_map: dict[str, str]):
    lines = [
        "# Master AI Functions",
        "# Merged from original and extended hunts",
        "# Format: FunctionName @ 0xOFFSET",
        "",
    ]

    def off_key(item: tuple[str, str]) -> int:
        try:
            return int(item[1], 16)
        except ValueError:
            return 0

    for name, off in sorted(func_map.items(), key=off_key):
        lines.append(f"{name} @ {off}")

    path.write_text("\n".join(lines))


def main():
    hook_orig = ROOT / "coa_ai_hook_points.txt"
    hook_ext = ROOT / "coa_ai_extended_hooks.txt"
    func_orig = ROOT / "coa_ai_functions.txt"
    func_ext = ROOT / "coa_ai_extended.txt"

    hooks_a = parse_hook_file(hook_orig) if hook_orig.exists() else {}
    hooks_b = parse_hook_file(hook_ext) if hook_ext.exists() else {}
    funcs_a = parse_functions_file(func_orig) if func_orig.exists() else {}
    funcs_b = parse_functions_file(func_ext) if func_ext.exists() else {}

    name_to_offset, offset_to_names = merge_hooks(hooks_a, hooks_b)
    merged_funcs = merge_functions(funcs_a, funcs_b)

    write_hooks(ROOT / "coa_ai_master_hooks.txt", name_to_offset, offset_to_names)
    write_functions(ROOT / "coa_ai_master_functions.txt", merged_funcs)

    print(f"Hooks merged: {len(name_to_offset)} names, {len(offset_to_names)} unique offsets")
    print(f"Functions merged: {len(merged_funcs)} entries")
    print("Wrote coa_ai_master_hooks.txt and coa_ai_master_functions.txt")


if __name__ == "__main__":
    main()
