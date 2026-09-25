#!/usr/bin/env python3
"""Aggregate guest profiling metrics JSON (dumped by scroll-zkvm-prover's
`perf-metrics` feature via PROFILE_METRICS_DIR) into human-readable tops:

  - top functions by executed instructions ("frequency"), self-attribution
    (leaf frame of the cycle tracker span stack)
  - top inclusive span stacks (flamegraph-style), also written as .stacks
  - top AIRs by cells used ("cells_used")

Function spans are decimal offsets into the guest symbols string table
(dumped by build-guest as guest.symbols when built with `perf-metrics`).

Usage: profile_top.py metrics.json [--symbols guest.symbols] [--top 30]
"""

import argparse
import json
import sys
from collections import defaultdict


def load_symbols(path):
    if not path:
        return None
    with open(path, "rb") as f:
        return f.read()


def resolve(name, symbols):
    """Resolve a span frame: decimal offset into the string table, or a plain name."""
    if symbols is None or not name or not name.isdigit():
        return name
    offset = int(name)
    end = symbols.find(b"\0", offset)
    if end == -1 or offset >= len(symbols):
        return name
    return symbols[offset:end].decode(errors="replace")


def shorten(name, maxlen=110):
    """Collapse verbose Rust paths: keep the last meaningful segments."""
    if len(name) <= maxlen:
        return name
    # strip generic args for readability
    out = []
    depth = 0
    for ch in name:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        elif depth == 0:
            out.append(ch)
    name = "".join(out)
    if len(name) > maxlen:
        name = "..." + name[-maxlen:]
    return name


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("metrics_json")
    ap.add_argument("--symbols", default=None)
    ap.add_argument("--top", type=int, default=30)
    args = ap.parse_args()

    with open(args.metrics_json) as f:
        data = json.load(f)

    symbols = load_symbols(args.symbols)

    instr_self = defaultdict(int)      # leaf function -> instructions
    instr_inclusive = defaultdict(int) # full stack -> instructions
    cells_air = defaultdict(int)       # air name -> cells
    cells_span_air = defaultdict(int)  # (span leaf fn, air) -> cells

    for entry in data.get("counter", []):
        metric = entry["metric"]
        labels = dict(entry["labels"])
        value = int(entry["value"])
        span = labels.get("cycle_tracker_span", "")
        frames = [resolve(f, symbols) for f in span.split(";") if f != ""]
        leaf = frames[-1] if frames else "<root>"

        if metric == "frequency":
            instr_self[leaf] += value
            instr_inclusive[";".join(frames)] += value
        elif metric == "cells_used":
            air = labels.get("air_name", "?")
            cells_air[air] += value
            cells_span_air[(leaf, air)] += value

    total_instr = sum(instr_self.values())
    total_cells = sum(cells_air.values())

    print(f"== total guest instructions (frequency): {total_instr:,}")
    print(f"== total trace cells (cells_used):       {total_cells:,}")
    print()
    print(f"-- top {args.top} functions by instructions (self) --")
    for name, v in sorted(instr_self.items(), key=lambda kv: -kv[1])[: args.top]:
        print(f"{v:>14,}  {100.0*v/max(total_instr,1):5.1f}%  {shorten(name)}")
    print()
    print(f"-- top {args.top} AIRs by cells used --")
    for name, v in sorted(cells_air.items(), key=lambda kv: -kv[1])[: args.top]:
        print(f"{v:>14,}  {100.0*v/max(total_cells,1):5.1f}%  {name}")
    print()
    print(f"-- top {args.top} (function, AIR) by cells used --")
    for (fn, air), v in sorted(cells_span_air.items(), key=lambda kv: -kv[1])[: args.top]:
        print(f"{v:>14,}  {100.0*v/max(total_cells,1):5.1f}%  {air}  <-  {shorten(fn, 80)}")
    print()
    print(f"-- top {args.top} inclusive span stacks by instructions --")
    for stack, v in sorted(instr_inclusive.items(), key=lambda kv: -kv[1])[: args.top]:
        print(f"{v:>14,}  {100.0*v/max(total_instr,1):5.1f}%  {shorten(stack, 160)}")


if __name__ == "__main__":
    main()
