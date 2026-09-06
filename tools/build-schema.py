#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bijstaan
"""
Generate the osquery schema catalog shipped with the plugin.

The catalog drives the live-query console's autocomplete: table names, their
columns and types, per-platform availability, and the upstream descriptions
(which become hover documentation). It is generated rather than hand-written so
that bumping the pinned osquery version is a one-command change.

Source of truth is osquery's own `specs/*.table` files, pulled once as a repo
tarball for the pinned tag. Platform availability comes from the directory a
spec lives in, which is how osquery itself decides it:

    specs/            all platforms
    specs/posix/      linux + darwin
    specs/macwin/     darwin + windows
    specs/linux/      linux
    specs/darwin/     darwin
    specs/windows/    windows
    specs/utility/    all platforms
    specs/sleuthkit/  skipped (requires a build flag most packages omit)

Usage:  tools/build-schema.py [version] [-o plugin/data/osquery-schema.json]
"""

import argparse
import ast
import io
import json
import pathlib
import re
import sys
import tarfile
import urllib.request

DIR_PLATFORMS = {
    "": ["darwin", "linux", "windows"],
    "utility": ["darwin", "linux", "windows"],
    "posix": ["darwin", "linux"],
    "macwin": ["darwin", "windows"],
    "linwin": ["linux", "windows"],
    "linux": ["linux"],
    "darwin": ["darwin"],
    "windows": ["windows"],
    "smart": ["darwin", "linux"],
    "yara": ["darwin", "linux", "windows"],
    "kernel": ["darwin"],
}

SKIP_DIRS = {"sleuthkit", "test"}

# Column("name", TYPE, "description", extras...) — description is optional.
COLUMN_RE = re.compile(
    r'Column\(\s*"(?P<name>[^"]+)"\s*,\s*(?P<type>\w+)\s*(?:,\s*(?P<desc>"(?:[^"\\]|\\.)*"))?',
    re.S,
)
TABLE_RE = re.compile(r'table_name\(\s*"([^"]+)"')
DESC_RE = re.compile(r'description\(\s*("(?:[^"\\]|\\.)*"|\'\'\'.*?\'\'\')', re.S)


def unquote(raw: str) -> str:
    if raw is None:
        return ""
    try:
        return " ".join(str(ast.literal_eval(raw)).split())
    except (ValueError, SyntaxError):
        return " ".join(raw.strip("\"'").split())


def parse_spec(text: str, platforms: list[str]) -> dict | None:
    table = TABLE_RE.search(text)
    if not table:
        return None

    columns = []
    seen = set()
    for m in COLUMN_RE.finditer(text):
        name = m.group("name")
        if name in seen:
            continue
        seen.add(name)
        columns.append(
            {
                "name": name,
                "type": m.group("type"),
                "description": unquote(m.group("desc")),
            }
        )

    desc = DESC_RE.search(text)

    return {
        "name": table.group(1),
        "description": unquote(desc.group(1)) if desc else "",
        "platforms": platforms,
        "columns": columns,
        # Evented tables only produce rows while osqueryd has been running, which
        # is a real gotcha when someone live-queries one and gets nothing back.
        "evented": "attributes(event_subscriber=True)" in text.replace(" ", ""),
    }


def build(version: str) -> dict:
    url = f"https://github.com/osquery/osquery/archive/refs/tags/{version}.tar.gz"
    print(f"fetching {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=120) as resp:
        payload = resp.read()

    tables = {}
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
        for member in tar.getmembers():
            parts = pathlib.PurePosixPath(member.name).parts
            if len(parts) < 3 or parts[1] != "specs" or not member.name.endswith(".table"):
                continue

            subdir = parts[2] if len(parts) > 3 else ""
            if subdir in SKIP_DIRS:
                continue
            platforms = DIR_PLATFORMS.get(subdir)
            if platforms is None:
                print(f"  ? unknown spec dir '{subdir}', treating as all platforms", file=sys.stderr)
                platforms = DIR_PLATFORMS[""]

            fh = tar.extractfile(member)
            if fh is None:
                continue

            parsed = parse_spec(fh.read().decode("utf-8", "replace"), platforms)
            if parsed is None:
                continue

            # A table defined in more than one platform directory (e.g. a linux
            # and a darwin implementation) is one table available on both.
            existing = tables.get(parsed["name"])
            if existing:
                existing["platforms"] = sorted(set(existing["platforms"]) | set(platforms))
                known = {c["name"] for c in existing["columns"]}
                existing["columns"].extend(c for c in parsed["columns"] if c["name"] not in known)
            else:
                tables[parsed["name"]] = parsed

    return {
        "osquery_version": version,
        "tables": [tables[name] for name in sorted(tables)],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", default="5.19.0")
    parser.add_argument(
        "-o",
        "--output",
        default=str(pathlib.Path(__file__).resolve().parent.parent / "plugin" / "data" / "osquery-schema.json"),
    )
    args = parser.parse_args()

    catalog = build(args.version)

    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(catalog, separators=(",", ":")), encoding="utf-8")

    total_cols = sum(len(t["columns"]) for t in catalog["tables"])
    evented = sum(1 for t in catalog["tables"] if t["evented"])
    by_plat = {
        p: sum(1 for t in catalog["tables"] if p in t["platforms"])
        for p in ("linux", "darwin", "windows")
    }
    print(
        f"wrote {out} — {len(catalog['tables'])} tables, {total_cols} columns, "
        f"{evented} evented; per platform {by_plat}",
        file=sys.stderr,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
