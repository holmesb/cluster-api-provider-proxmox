#!/usr/bin/env python3
"""Estimate PR 'new/changed line' coverage from Go coverprofile + git diff.

Why: SonarCloud's 'Coverage on New Code' is usually computed over lines changed in the PR.
If you can't access SonarCloud UI, this gives you a concrete list of uncovered changed lines.

Usage (run from repo root):
  1) Generate coverage:
       make test
       go test ./... -coverprofile=cover.out   # if make test doesn't emit one
  2) Ensure you have an up-to-date base ref (adjust as needed):
       git fetch origin main
  3) Run:
       python3 ./pr_cov_helper.py --base origin/main --cover cover.out

Outputs:
  - Estimated % covered on changed lines
  - Per-file covered/uncovered changed lines
  - A list of uncovered changed line numbers per file

Notes:
  - This is an approximation of Sonar's 'new code' definition, but is usually close enough
    to identify exactly what you need to test.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Tuple


@dataclass(frozen=True)
class Block:
    file: str
    start_line: int
    end_line: int
    stmts: int
    hits: int


HUNK_RE = re.compile(r"^@@ -(?:\d+)(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def run(cmd: List[str]) -> str:
    p = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.stdout


def parse_changed_lines(base_ref: str) -> Dict[str, Set[int]]:
    """Return {file: {changed_line_numbers}} for added/modified lines."""
    diff = run(["git", "diff", "--unified=0", base_ref, "--"])  # zero context
    changed: Dict[str, Set[int]] = {}

    cur_file: str | None = None
    new_line = 0

    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            cur_file = line[len("+++ b/") :]
            if cur_file == "/dev/null":
                cur_file = None
            continue
        if cur_file is None:
            continue

        m = HUNK_RE.match(line)
        if m:
            new_line = int(m.group(1))
            continue

        # Added lines start with '+' (but not '+++')
        if line.startswith("+") and not line.startswith("+++"):
            changed.setdefault(cur_file, set()).add(new_line)
            new_line += 1
            continue

        # Context lines (shouldn't occur with -U0, but handle anyway)
        if line.startswith(" "):
            new_line += 1
            continue

        # Removed lines don't advance new-line counter
        if line.startswith("-") and not line.startswith("---"):
            continue

    return changed


def parse_coverprofile(path: str) -> List[Block]:
    blocks: List[Block] = []
    with open(path, "r", encoding="utf-8") as f:
        header = f.readline().strip()
        if not header.startswith("mode:"):
            raise ValueError(f"Not a coverprofile (missing mode:): {header}")
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            # format: file:startLine.startCol,endLine.endCol stmts hits
            left, stmts_s, hits_s = ln.split(" ")
            file_part, rng = left.split(":", 1)
            start, end = rng.split(",")
            start_line = int(start.split(".")[0])
            end_line = int(end.split(".")[0])
            blocks.append(Block(file=file_part, start_line=start_line, end_line=end_line, stmts=int(stmts_s), hits=int(hits_s)))
    return blocks


def normalise_file_path(p: str) -> str:
    # coverprofile entries are usually module paths like github.com/org/repo/dir/file.go
    # Convert to repo-relative path by stripping everything up to the module name.
    # This repo's module path is 'github.com/ionos-cloud/cluster-api-provider-proxmox'.
    marker = "github.com/ionos-cloud/cluster-api-provider-proxmox/"
    if marker in p:
        return p.split(marker, 1)[1]
    return p


def build_line_coverage(blocks: List[Block]) -> Dict[str, Dict[int, Tuple[int, int]]]:
    """Return {file: {line: (stmts, hits)}} aggregated across blocks."""
    per_file: Dict[str, Dict[int, Tuple[int, int]]] = {}
    for b in blocks:
        f = normalise_file_path(b.file)
        m = per_file.setdefault(f, {})
        for line in range(b.start_line, b.end_line + 1):
            s, h = m.get(line, (0, 0))
            m[line] = (s + b.stmts, h + (b.stmts if b.hits > 0 else 0))
    return per_file


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="origin/main", help="Base ref to diff against (default: origin/main)")
    ap.add_argument("--cover", default="cover.out", help="Go coverprofile path (default: cover.out)")
    args = ap.parse_args()

    changed = parse_changed_lines(args.base)
    blocks = parse_coverprofile(args.cover)
    cov = build_line_coverage(blocks)

    total_stmts = 0
    hit_stmts = 0

    per_file_report: List[Tuple[str, int, int, List[int]]] = []

    for f, lines in sorted(changed.items()):
        file_cov = cov.get(f, {})
        file_total = 0
        file_hit = 0
        uncovered: List[int] = []

        for ln in sorted(lines):
            stmts, hits = file_cov.get(ln, (0, 0))
            # If stmts==0, it's often a blank/comment line; ignore it.
            if stmts == 0:
                continue
            file_total += stmts
            file_hit += hits
            if hits == 0:
                uncovered.append(ln)

        if file_total:
            per_file_report.append((f, file_hit, file_total, uncovered))
            total_stmts += file_total
            hit_stmts += file_hit

    if total_stmts == 0:
        print("No statement-bearing changed lines found (or coverage file didn't map).")
        print("If you expected results, ensure: (1) you generated cover.out, (2) base ref is correct, (3) module path matches.")
        return 2

    pct = 100.0 * hit_stmts / total_stmts
    print(f"Estimated PR coverage on changed lines: {pct:.1f}%  ({hit_stmts}/{total_stmts} statements)")
    print()

    for f, h, t, uncovered in per_file_report:
        fpct = 100.0 * h / t
        print(f"{f}: {fpct:.1f}% ({h}/{t})")
        if uncovered:
            print(f"  Uncovered changed lines: {', '.join(map(str, uncovered[:50]))}{' …' if len(uncovered) > 50 else ''}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

