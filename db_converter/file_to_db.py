#!/usr/bin/env python3
"""
file_to_db.py — Universal File-to-DB Converter

Detects the format of any input file and converts its structured content
into a SQLite .db file with proper schema inference.

Supported formats:
  CSV, TSV, JSON, JSONL, XML, Excel (.xlsx/.xls), plain-text (delimited)

Usage:
  python file_to_db.py <input_file> [-o output.db] [-t table_name]
"""

import argparse
import csv
import json
import os
import re
import sqlite3
import sys
import xml.etree.ElementTree as ET
from io import StringIO
from pathlib import Path

# ── Colour helpers (Windows-safe) ────────────────────────────────────────────

def _supports_colour():
    if os.name == "nt":
        os.system("")  # enable ANSI on Windows 10+
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

_COLOUR = _supports_colour()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _COLOUR else text

def green(t):  return _c("1;32", t)
def cyan(t):   return _c("1;36", t)
def yellow(t): return _c("1;33", t)
def red(t):    return _c("1;31", t)
def bold(t):   return _c("1", t)
def dim(t):    return _c("2", t)


# ── Format detection ─────────────────────────────────────────────────────────

EXTENSION_MAP = {
    ".csv":   "csv",
    ".tsv":   "tsv",
    ".json":  "json",
    ".jsonl": "jsonl",
    ".xml":   "xml",
    ".xlsx":  "excel",
    ".xls":   "excel",
}

DELIMITERS = [",", "\t", "|", ";"]


def detect_format(filepath: str) -> str:
    """Return a format string based on extension + content sniffing."""
    ext = Path(filepath).suffix.lower()

    if ext in EXTENSION_MAP:
        return EXTENSION_MAP[ext]

    # For .txt / .log / .dat / unknown — sniff for a common delimiter
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            sample = f.read(8192)
        dialect = csv.Sniffer().sniff(sample, delimiters="".join(DELIMITERS))
        if dialect.delimiter == "\t":
            return "tsv"
        return "delimited"
    except csv.Error:
        return "text"  # unstructured fallback


# ── Parsers ──────────────────────────────────────────────────────────────────

def _read_lines(filepath):
    """Yield lines from a file, handling encoding gracefully."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        yield from f


def parse_csv(filepath: str):
    """Parse CSV file → (columns, rows)."""
    with open(filepath, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
        sample = f.read(8192)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",")
        except csv.Error:
            dialect = csv.excel
        reader = csv.reader(f, dialect)
        columns = next(reader, None)
        if columns is None:
            return [], []
        rows = [row for row in reader if any(cell.strip() for cell in row)]
    return columns, rows


def parse_tsv(filepath: str):
    """Parse TSV file → (columns, rows)."""
    with open(filepath, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
        reader = csv.reader(f, delimiter="\t")
        columns = next(reader, None)
        if columns is None:
            return [], []
        rows = [row for row in reader if any(cell.strip() for cell in row)]
    return columns, rows


def parse_delimited(filepath: str):
    """Parse a delimited text file by sniffing the delimiter."""
    with open(filepath, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
        sample = f.read(8192)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters="".join(DELIMITERS))
        reader = csv.reader(f, dialect)
        columns = next(reader, None)
        if columns is None:
            return [], []
        rows = [row for row in reader if any(cell.strip() for cell in row)]
    return columns, rows


def parse_json(filepath: str):
    """Parse a JSON file (array of objects) → (columns, rows)."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    if isinstance(data, dict):
        # If the root is a dict, look for the first key whose value is a list
        for key, val in data.items():
            if isinstance(val, list) and len(val) > 0 and isinstance(val[0], dict):
                data = val
                break
        else:
            # Treat a flat dict as a single-row table
            data = [data]

    if not isinstance(data, list) or len(data) == 0:
        return [], []

    if isinstance(data[0], dict):
        # Collect all keys across every object to handle ragged data
        all_keys = list(dict.fromkeys(k for obj in data for k in obj.keys()))
        rows = [[str(obj.get(k, "")) for k in all_keys] for obj in data]
        return all_keys, rows

    # Flat list of scalars → single-column table
    return ["value"], [[str(v)] for v in data]


def parse_jsonl(filepath: str):
    """Parse a JSONL (one JSON object per line) → (columns, rows)."""
    objects = []
    for line in _read_lines(filepath):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                objects.append(obj)
        except json.JSONDecodeError:
            continue

    if not objects:
        return [], []

    all_keys = list(dict.fromkeys(k for obj in objects for k in obj.keys()))
    rows = [[str(obj.get(k, "")) for k in all_keys] for obj in objects]
    return all_keys, rows


def parse_xml(filepath: str):
    """Parse an XML file → (columns, rows).

    Strategy: find the first repeating child element and treat each
    occurrence as a row. Attributes + sub-element text become columns.
    """
    tree = ET.parse(filepath)
    root = tree.getroot()

    # Strip namespace for simpler tag comparison
    def _local(tag):
        return tag.split("}")[-1] if "}" in tag else tag

    # Identify the most frequent direct child tag → those are our "rows"
    tag_counts = {}
    for child in root:
        tag = _local(child.tag)
        tag_counts[tag] = tag_counts.get(tag, 0) + 1

    if not tag_counts:
        return [], []

    row_tag = max(tag_counts, key=tag_counts.get)
    row_elements = [c for c in root if _local(c.tag) == row_tag]

    # Collect all possible column names from attributes + children
    all_keys = list(dict.fromkeys(
        k
        for elem in row_elements
        for k in (
            list(elem.attrib.keys()) +
            [_local(sub.tag) for sub in elem]
        )
    ))

    if not all_keys:
        # Elements might just have text
        all_keys = ["value"]
        rows = [[(e.text or "").strip()] for e in row_elements]
        return all_keys, rows

    rows = []
    for elem in row_elements:
        row = []
        for key in all_keys:
            if key in elem.attrib:
                row.append(elem.attrib[key])
            else:
                sub = elem.find(key) or elem.find(f".//{key}")
                if sub is None:
                    # Try with namespace wildcard
                    for child in elem:
                        if _local(child.tag) == key:
                            sub = child
                            break
                row.append((sub.text or "").strip() if sub is not None else "")
        rows.append(row)

    return all_keys, rows


def parse_excel(filepath: str):
    """Parse an Excel file (.xlsx / .xls) → (columns, rows)."""
    try:
        import openpyxl
    except ImportError:
        print(red("✗ ") + "openpyxl is required for Excel files.")
        print(dim("  Install it:  pip install openpyxl"))
        sys.exit(1)

    wb = openpyxl.load_workbook(filepath, read_only=True, data_only=True)
    ws = wb.active
    data = list(ws.iter_rows(values_only=True))
    wb.close()

    if not data:
        return [], []

    columns = [str(c) if c is not None else f"col_{i}" for i, c in enumerate(data[0])]
    rows = [[str(cell) if cell is not None else "" for cell in row] for row in data[1:]]
    return columns, rows


def parse_text(filepath: str):
    """Fallback: store every non-empty line as a row in a 'content' column."""
    rows = []
    for line in _read_lines(filepath):
        stripped = line.rstrip("\n\r")
        if stripped:
            rows.append([stripped])
    return ["content"], rows


PARSERS = {
    "csv":       parse_csv,
    "tsv":       parse_tsv,
    "delimited": parse_delimited,
    "json":      parse_json,
    "jsonl":     parse_jsonl,
    "xml":       parse_xml,
    "excel":     parse_excel,
    "text":      parse_text,
}


def parse_file(filepath: str, fmt: str):
    """Dispatch to the correct parser and return (columns, rows)."""
    parser = PARSERS.get(fmt)
    if parser is None:
        print(red(f"✗  No parser for format '{fmt}'"))
        sys.exit(1)
    return parser(filepath)


# ── Column sanitiser & type inference ────────────────────────────────────────

_CLEAN_RE = re.compile(r"[^a-zA-Z0-9_]")


def sanitise_column(name: str) -> str:
    """Turn an arbitrary header string into a safe SQLite identifier."""
    name = name.strip()
    name = _CLEAN_RE.sub("_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    if not name or name[0].isdigit():
        name = "col_" + name
    return name.lower()


def infer_type(values):
    """Return 'INTEGER', 'REAL', or 'TEXT' for a list of string values."""
    int_ok = True
    real_ok = True
    for v in values:
        v = v.strip()
        if not v:
            continue
        try:
            int(v)
            continue
        except ValueError:
            int_ok = False
        try:
            float(v)
            continue
        except ValueError:
            real_ok = False
            break

    if int_ok:
        return "INTEGER"
    if real_ok:
        return "REAL"
    return "TEXT"


# ── Database writer ──────────────────────────────────────────────────────────

def write_to_db(columns, rows, db_path: str, table_name: str):
    """Create (or replace) a SQLite table and insert all rows."""
    if not columns:
        print(yellow("⚠  No columns found — nothing to write."))
        return

    # Sanitise column names (keep originals for display)
    safe_cols = [sanitise_column(c) for c in columns]

    # Deduplicate column names
    seen = {}
    deduped = []
    for col in safe_cols:
        if col in seen:
            seen[col] += 1
            deduped.append(f"{col}_{seen[col]}")
        else:
            seen[col] = 0
            deduped.append(col)
    safe_cols = deduped

    # Sample up to 500 rows for type inference
    sample_size = min(500, len(rows))
    col_types = []
    for i in range(len(safe_cols)):
        sample_vals = [
            rows[j][i] if i < len(rows[j]) else ""
            for j in range(sample_size)
        ]
        col_types.append(infer_type(sample_vals))

    # Build CREATE TABLE
    col_defs = ", ".join(
        f'"{col}" {typ}' for col, typ in zip(safe_cols, col_types)
    )
    create_sql = f'CREATE TABLE IF NOT EXISTS "{table_name}" (id INTEGER PRIMARY KEY AUTOINCREMENT, {col_defs})'

    placeholders = ", ".join(["?"] * len(safe_cols))
    quoted_cols = ", ".join('"' + c + '"' for c in safe_cols)
    insert_sql = f'INSERT INTO "{table_name}" ({quoted_cols}) VALUES ({placeholders})'

    # Normalise row lengths
    norm_rows = []
    expected = len(safe_cols)
    for row in rows:
        if len(row) < expected:
            row = row + [""] * (expected - len(row))
        elif len(row) > expected:
            row = row[:expected]
        norm_rows.append(tuple(row))

    # Write
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(f'DROP TABLE IF EXISTS "{table_name}"')
    cur.execute(create_sql)
    cur.executemany(insert_sql, norm_rows)
    conn.commit()
    conn.close()


# ── CLI ──────────────────────────────────────────────────────────────────────

def _default_table(filepath: str) -> str:
    """Derive a table name from the file's base name."""
    stem = Path(filepath).stem
    return sanitise_column(stem) or "data"


def _human_size(nbytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if nbytes < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} TB"


def main():
    parser = argparse.ArgumentParser(
        description="Convert any structured file into a SQLite .db database.",
        epilog="Supported formats: CSV, TSV, JSON, JSONL, XML, Excel, delimited text.",
    )
    parser.add_argument("input", help="Path to the input file")
    parser.add_argument("-o", "--output", help="Output .db file path (default: <input>.db)")
    parser.add_argument("-t", "--table", help="Table name (default: derived from filename)")
    args = parser.parse_args()

    filepath = os.path.abspath(args.input)

    # Validate input
    if not os.path.isfile(filepath):
        print(red(f"✗  File not found: {filepath}"))
        sys.exit(1)

    # Defaults
    db_path = args.output or str(Path(filepath).with_suffix(".db"))
    table_name = args.table or _default_table(filepath)

    # ── Step 1: Detect format ────────────────────────────────────────────
    fmt = detect_format(filepath)
    print(bold("┌─────────────────────────────────────────────┐"))
    print(bold("│") + cyan("   File → DB Converter                       ") + bold("│"))
    print(bold("└─────────────────────────────────────────────┘"))
    print()
    print(f"  {dim('Input')}   : {bold(os.path.basename(filepath))}")
    print(f"  {dim('Format')}  : {green(fmt.upper())}")
    print(f"  {dim('Output')}  : {bold(os.path.basename(db_path))}")
    print(f"  {dim('Table')}   : {cyan(table_name)}")
    print()

    # ── Step 2: Parse ────────────────────────────────────────────────────
    try:
        columns, rows = parse_file(filepath, fmt)
    except Exception as e:
        print(red(f"✗  Failed to parse file: {e}"))
        sys.exit(1)

    if not columns:
        print(yellow("⚠  No data could be extracted from the file."))
        sys.exit(0)

    print(f"  {dim('Columns')} : {len(columns)}")
    print(f"  {dim('Rows')}    : {len(rows)}")

    # ── Step 3: Write to DB ──────────────────────────────────────────────
    try:
        write_to_db(columns, rows, db_path, table_name)
    except Exception as e:
        print(red(f"\n✗  Failed to write database: {e}"))
        sys.exit(1)

    db_size = os.path.getsize(db_path)
    print()
    print(green("  ✓ ") + f"Database created: {bold(db_path)}")
    print(f"  {dim('Size')}    : {_human_size(db_size)}")
    print(f"  {dim('Rows')}    : {green(str(len(rows)))}")
    print()


if __name__ == "__main__":
    main()
