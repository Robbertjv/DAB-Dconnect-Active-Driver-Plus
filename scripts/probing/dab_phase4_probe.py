#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dab_phase4_probe.py
===================

DAB Active Driver Plus M/M 1.5 -- CAN probe harness, phase 4.

WHY THIS PHASE EXISTS
---------------------
Phases 1-3 swept the 29-bit identifier exhaustively (8192 "families",
32 tokens) while holding the *request form* completely constant:

    DLC 5, payload  01 00 00 <tok_lo> <tok_hi>

Every TX frame this project has ever emitted was DLC 5 or DLC 7.
DLC 0,1,2,3,4,6,8 have never been sent. The assumption that a request
must mirror the form of the device's own broadcast frames was never
tested. Most higher-layer CAN protocols mandate fixed 8-byte service
requests; if that applies here, every prior "no response" means
"malformed request", not "nothing there".

This harness sweeps the axes that were previously frozen:
    - DLC              (0..8)
    - opcode byte 0    (0x00..0xFF)
    - body bytes 1..2  (always 00 so far)
    - identifier bitfields (instead of the assumed family/token split)

LOGGING CONVENTION (new in phase 4)
-----------------------------------
    <test>_<soort>_<YYYYMMDD-HHMMSS>.<ext>

    test   logical test name           e.g. dlc-sweep
    soort  log type                    meta | raw | probe | event | summary
    stamp  ONE shared session stamp, identical across all files of a run

    dlc-sweep_meta_20260930-181500.json
    dlc-sweep_raw_20260930-181500.csv
    dlc-sweep_probe_20260930-181500.csv
    dlc-sweep_event_20260930-181500.csv
    dlc-sweep_summary_20260930-181500.json

DELIBERATE CHANGE: the raw log stores the RAW 29-bit identifier only.
No family_hex / token_hex columns. Pre-committing to a decomposition in
the logger is what froze the wrong hypothesis into three phases of work.
Decompose at analysis time, where it can be corrected for free.

SAFETY
------
Dry-run is the default. Injection requires an explicit --send.
The run aborts on CAN error frames unless --ignore-errors is given.

Requires: python-can >= 4.0   (pip install python-can)
"""

from __future__ import annotations

import argparse
import csv
import json
import signal
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Sequence

try:
    import can
except ImportError:  # pragma: no cover
    can = None


# --------------------------------------------------------------------------
# Configuration defaults
# --------------------------------------------------------------------------

DEFAULT_INJECTOR = "PCAN_USBBUS1"
DEFAULT_OBSERVER = "PCAN_USBBUS2"
DEFAULT_BITRATE = 1_000_000
DEFAULT_INTERFACE = "pcan"
DEFAULT_OUTDIR = "dab_phase4_results"

# Confirmed responder family from phase 3 (kept only as a convenient default).
DEFAULT_FAMILY = 0x0012
DEFAULT_TOKEN = 0xC82D

# Identifiers the device emits unprompted. Used ONLY to classify a frame as
# "background" vs "novel" -- never to decode structure.
BACKGROUND_ID_MASK = 0xFFFF0000
BACKGROUND_ID_VALUES = {0x00010000, 0x00110000}

LOG_KINDS = ("meta", "raw", "probe", "event", "summary")


# --------------------------------------------------------------------------
# Session logging
# --------------------------------------------------------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def session_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


class SessionLogger:
    """
    Owns the <test>_<soort>_<stamp>.<ext> naming convention and all writers.

    One stamp is generated per session and reused for every file, so a run's
    artefacts sort together and can never be mismatched across runs.
    """

    RAW_FIELDS = [
        "utc",
        "host_rel_ms",
        "adapter",
        "direction",
        "phase",
        "probe_index",
        "can_id_hex",      # RAW 29-bit id. No decomposition. Deliberate.
        "extended",
        "dlc",
        "data_hex",
        "is_error",
        "status",
    ]

    PROBE_FIELDS = [
        "utc",
        "test",
        "probe_index",
        "param_name",
        "param_value",
        "tx_can_id_hex",
        "tx_dlc",
        "tx_data_hex",
        "tx_ok",
        "pre_frames",
        "post_frames",
        "novel_frames",
        "novel_ids",
        "novel_payloads",
        "first_latency_ms",
        "last_latency_ms",
        "error_frames",
        "operator_note",
    ]

    EVENT_FIELDS = ["utc", "host_rel_ms", "event", "details"]

    def __init__(self, test: str, outdir: Path, stamp: str | None = None):
        self.test = test
        self.stamp = stamp or session_stamp()
        self.outdir = Path(outdir)
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.t0 = time.perf_counter()

        self._raw_fh = self.path("raw", "csv").open("w", newline="", encoding="utf-8")
        self._raw = csv.DictWriter(self._raw_fh, fieldnames=self.RAW_FIELDS)
        self._raw.writeheader()

        self._probe_fh = self.path("probe", "csv").open("w", newline="", encoding="utf-8")
        self._probe = csv.DictWriter(self._probe_fh, fieldnames=self.PROBE_FIELDS)
        self._probe.writeheader()

        self._event_fh = self.path("event", "csv").open("w", newline="", encoding="utf-8")
        self._event = csv.DictWriter(self._event_fh, fieldnames=self.EVENT_FIELDS)
        self._event.writeheader()

    # -- naming -----------------------------------------------------------

    def path(self, soort: str, ext: str) -> Path:
        if soort not in LOG_KINDS:
            raise ValueError(f"unknown log kind {soort!r}; expected one of {LOG_KINDS}")
        return self.outdir / f"{self.test}_{soort}_{self.stamp}.{ext}"

    def rel_ms(self) -> float:
        return round((time.perf_counter() - self.t0) * 1000.0, 3)

    # -- writers ----------------------------------------------------------

    def meta(self, payload: dict) -> None:
        payload = dict(payload)
        payload.update(test=self.test, stamp=self.stamp, created_utc=utc_now_iso())
        self.path("meta", "json").write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )

    def summary(self, payload: dict) -> None:
        payload = dict(payload)
        payload.update(test=self.test, stamp=self.stamp, closed_utc=utc_now_iso())
        self.path("summary", "json").write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )

    def event(self, event: str, details: str = "") -> None:
        self._event.writerow({
            "utc": utc_now_iso(),
            "host_rel_ms": self.rel_ms(),
            "event": event,
            "details": details,
        })
        self._event_fh.flush()

    def raw(self, *, adapter: str, direction: str, phase: str,
            probe_index: int, msg, status: str = "OK") -> None:
        self._raw.writerow({
            "utc": utc_now_iso(),
            "host_rel_ms": self.rel_ms(),
            "adapter": adapter,
            "direction": direction,
            "phase": phase,
            "probe_index": probe_index,
            "can_id_hex": f"{msg.arbitration_id:08X}",
            "extended": int(bool(msg.is_extended_id)),
            "dlc": msg.dlc,
            "data_hex": " ".join(f"{b:02X}" for b in msg.data),
            "is_error": int(bool(getattr(msg, "is_error_frame", False))),
            "status": status,
        })

    def probe(self, row: dict) -> None:
        self._probe.writerow({k: row.get(k, "") for k in self.PROBE_FIELDS})
        self._probe_fh.flush()

    def flush(self) -> None:
        self._raw_fh.flush()
        self._probe_fh.flush()
        self._event_fh.flush()

    def close(self) -> None:
        for fh in (self._raw_fh, self._probe_fh, self._event_fh):
            try:
                fh.close()
            except Exception:
                pass

    def manifest(self) -> dict:
        return {k: self.path(k, "json" if k in ("meta", "summary") else "csv").name
                for k in LOG_KINDS}


# --------------------------------------------------------------------------
# Probe definition
# --------------------------------------------------------------------------

@dataclass
class ProbeSpec:
    """A single frame to transmit, plus the swept parameter it represents."""
    can_id: int
    data: bytes
    param_name: str
    param_value: str
    dlc: int | None = None          # None -> len(data)

    @property
    def effective_dlc(self) -> int:
        return self.dlc if self.dlc is not None else len(self.data)

    def message(self):
        return can.Message(
            arbitration_id=self.can_id,
            is_extended_id=True,
            data=self.data,
            dlc=self.effective_dlc,
        )

    def describe(self) -> str:
        body = " ".join(f"{b:02X}" for b in self.data) or "-"
        return (f"{self.param_name}={self.param_value:<18} "
                f"id={self.can_id:08X} dlc={self.effective_dlc} data=[{body}]")


# --------------------------------------------------------------------------
# Probe generators
# --------------------------------------------------------------------------

def token_bytes(token: int) -> bytes:
    """Little-endian token, as used by every frame observed so far."""
    return bytes((token & 0xFF, (token >> 8) & 0xFF))


def gen_dlc_sweep(family: int, token: int, padding: Sequence[str],
                  repeats: int) -> Iterator[ProbeSpec]:
    """
    THE priority experiment.

    Sweeps DLC 0..8 under three padding strategies, because "what goes in the
    extra bytes" is itself unknown:

        truncate  canonical 5-byte body cut or grown with 0x00
        zero      opcode + zeros
        repeat    canonical body repeated to fill

    9 DLCs x 3 strategies x repeats. At repeats=3 that is 81 probes.
    """
    can_id = (family << 16) | (token & 0xFFFF)
    canonical = bytes((0x01, 0x00, 0x00)) + token_bytes(token)

    for rep in range(1, repeats + 1):
        for strategy in padding:
            for dlc in range(0, 9):
                if strategy == "truncate":
                    body = canonical[:dlc] if dlc <= len(canonical) else \
                           canonical + bytes(dlc - len(canonical))
                elif strategy == "zero":
                    body = (bytes((0x01,)) + bytes(max(0, dlc - 1)))[:dlc]
                elif strategy == "repeat":
                    reps = (dlc // len(canonical)) + 1
                    body = (canonical * reps)[:dlc]
                else:
                    raise ValueError(f"unknown padding strategy {strategy!r}")

                yield ProbeSpec(
                    can_id=can_id,
                    data=body,
                    dlc=dlc,
                    param_name="dlc",
                    param_value=f"{dlc}/{strategy}/r{rep}",
                )


def gen_opcode_sweep(family: int, token: int, dlc: int,
                     lo: int, hi: int, repeats: int) -> Iterator[ProbeSpec]:
    """
    Byte 0 has been 0x01 in every frame ever sent. In a service protocol that
    is almost certainly a function code. Sweep it.
    """
    can_id = (family << 16) | (token & 0xFFFF)
    tail = bytes((0x00, 0x00)) + token_bytes(token)

    for rep in range(1, repeats + 1):
        for opcode in range(lo, hi + 1):
            body = (bytes((opcode,)) + tail)
            body = body[:dlc] if dlc <= len(body) else body + bytes(dlc - len(body))
            yield ProbeSpec(
                can_id=can_id,
                data=body,
                dlc=dlc,
                param_name="opcode",
                param_value=f"{opcode:02X}/r{rep}",
            )


def gen_body_sweep(family: int, token: int, dlc: int,
                   repeats: int) -> Iterator[ProbeSpec]:
    """
    Bytes 1 and 2 are 0x00 in 100% of observed traffic. Either they are
    reserved, or they are a sub-function / index that nothing has yet set.
    """
    can_id = (family << 16) | (token & 0xFFFF)
    interesting = [0x00, 0x01, 0x02, 0x03, 0x04, 0x08, 0x0F, 0x10,
                   0x20, 0x40, 0x7F, 0x80, 0xA0, 0xC0, 0xF0, 0xFF]

    for rep in range(1, repeats + 1):
        for pos in (1, 2):
            for val in interesting:
                body = bytearray(bytes((0x01, 0x00, 0x00)) + token_bytes(token))
                body[pos] = val
                body = bytes(body)
                body = body[:dlc] if dlc <= len(body) else body + bytes(dlc - len(body))
                yield ProbeSpec(
                    can_id=can_id,
                    data=body,
                    dlc=dlc,
                    param_name=f"byte{pos}",
                    param_value=f"{val:02X}/r{rep}",
                )


def gen_idfield_sweep(base_id: int, token: int, dlc: int,
                      repeats: int) -> Iterator[ProbeSpec]:
    """
    Walk single bits of the 29-bit identifier instead of assuming a
    [16-bit family][16-bit token] split.

    Phase 3 already proved bit 0x0800 is a don't-care for the receiver, which
    is direct evidence that the real field boundaries are NOT where we drew
    them. This enumerates all 29 single-bit mutations of a known-good id.
    """
    canonical = bytes((0x01, 0x00, 0x00)) + token_bytes(token)
    body = canonical[:dlc] if dlc <= len(canonical) else \
           canonical + bytes(dlc - len(canonical))

    for rep in range(1, repeats + 1):
        yield ProbeSpec(base_id, body, "idbit", f"base/r{rep}", dlc)
        for bit in range(29):
            mutated = base_id ^ (1 << bit)
            yield ProbeSpec(
                can_id=mutated & 0x1FFFFFFF,
                data=body,
                dlc=dlc,
                param_name="idbit",
                param_value=f"bit{bit:02d}/r{rep}",
            )


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------

@dataclass
class HarnessConfig:
    interface: str = DEFAULT_INTERFACE
    injector: str = DEFAULT_INJECTOR
    observer: str = DEFAULT_OBSERVER
    bitrate: int = DEFAULT_BITRATE
    send: bool = False
    pre_window: float = 0.30
    post_window: float = 0.60
    gap: float = 0.40
    settle: float = 2.0
    ignore_errors: bool = False
    error_abort_threshold: int = 25
    prompt: bool = False


class Harness:
    def __init__(self, cfg: HarnessConfig, log: SessionLogger):
        self.cfg = cfg
        self.log = log
        self.injector = None
        self.observer = None
        self._abort = False
        self.error_frames = 0
        self.stats = {"probes": 0, "responded": 0, "novel_frames": 0}

        signal.signal(signal.SIGINT, self._on_signal)

    def _on_signal(self, *_):
        self._abort = True
        self.log.event("signal_abort", "SIGINT")
        print("\n[abort] SIGINT received, finishing current probe...", file=sys.stderr)

    # -- bus lifecycle ----------------------------------------------------

    def open(self) -> None:
        if can is None:
            raise RuntimeError("python-can is not installed (pip install python-can)")

        self.observer = can.Bus(
            interface=self.cfg.interface,
            channel=self.cfg.observer,
            bitrate=self.cfg.bitrate,
        )
        self.log.event("observer_open", self.cfg.observer)

        if self.cfg.send:
            self.injector = can.Bus(
                interface=self.cfg.interface,
                channel=self.cfg.injector,
                bitrate=self.cfg.bitrate,
            )
            self.log.event("injector_open", self.cfg.injector)
        else:
            self.log.event("injector_skipped", "dry-run; no TX bus opened")

    def close(self) -> None:
        for bus, name in ((self.injector, "injector"), (self.observer, "observer")):
            if bus is not None:
                try:
                    bus.shutdown()
                    self.log.event(f"{name}_closed", "")
                except Exception as exc:
                    self.log.event(f"{name}_close_failed", repr(exc))

    # -- capture ----------------------------------------------------------

    def drain(self, seconds: float, phase: str, probe_index: int) -> list:
        """Capture for `seconds`, logging every frame. Returns the frames."""
        out = []
        deadline = time.perf_counter() + seconds
        while time.perf_counter() < deadline:
            remaining = deadline - time.perf_counter()
            msg = self.observer.recv(timeout=max(0.0, min(0.05, remaining)))
            if msg is None:
                continue
            if getattr(msg, "is_error_frame", False):
                self.error_frames += 1
                self.log.raw(adapter="observer", direction="RX", phase=phase,
                             probe_index=probe_index, msg=msg, status="ERROR_FRAME")
                self.log.event("can_error_frame", f"phase={phase}")
                continue
            self.log.raw(adapter="observer", direction="RX", phase=phase,
                         probe_index=probe_index, msg=msg)
            out.append(msg)
        return out

    @staticmethod
    def is_background(msg) -> bool:
        return (msg.arbitration_id & BACKGROUND_ID_MASK) in BACKGROUND_ID_VALUES

    # -- baseline ---------------------------------------------------------

    def baseline(self, seconds: float) -> dict:
        print(f"[baseline] passive capture, {seconds:.0f}s ...")
        self.log.event("baseline_started", f"{seconds}s")
        frames = self.drain(seconds, "baseline", 0)
        novel = [m for m in frames if not self.is_background(m)]
        ids = sorted({f"{m.arbitration_id:08X}" for m in frames})
        result = {
            "seconds": seconds,
            "frames": len(frames),
            "rate_hz": round(len(frames) / seconds, 1) if seconds else 0,
            "distinct_ids": len(ids),
            "novel_frames": len(novel),
            "novel_ids": sorted({f"{m.arbitration_id:08X}" for m in novel}),
            "dlc_histogram": {},
        }
        for m in frames:
            result["dlc_histogram"][str(m.dlc)] = \
                result["dlc_histogram"].get(str(m.dlc), 0) + 1

        self.log.event("baseline_completed", json.dumps(result))
        print(f"[baseline] {result['frames']} frames, "
              f"{result['rate_hz']} Hz, {result['novel_frames']} novel")
        if result["novel_frames"]:
            print(f"[baseline] !! spontaneous non-background ids: "
                  f"{result['novel_ids']}")
        return result

    # -- probing ----------------------------------------------------------

    def run_probe(self, index: int, spec: ProbeSpec) -> dict:
        phase = f"probe_{index:05d}"
        row = {
            "utc": utc_now_iso(),
            "test": self.log.test,
            "probe_index": index,
            "param_name": spec.param_name,
            "param_value": spec.param_value,
            "tx_can_id_hex": f"{spec.can_id:08X}",
            "tx_dlc": spec.effective_dlc,
            "tx_data_hex": " ".join(f"{b:02X}" for b in spec.data) or "",
            "tx_ok": "",
            "error_frames": 0,
        }

        if not self.cfg.send:
            print(f"  [dry] {spec.describe()}")
            row["tx_ok"] = "DRY_RUN"
            self.log.probe(row)
            return row

        errors_before = self.error_frames
        pre = self.drain(self.cfg.pre_window, f"{phase}_pre", index)

        msg = spec.message()
        try:
            self.injector.send(msg)
            row["tx_ok"] = "True"
            self.log.raw(adapter="injector", direction="TX", phase=f"{phase}_tx",
                         probe_index=index, msg=msg)
        except Exception as exc:
            row["tx_ok"] = f"False:{exc!r}"
            self.log.event("tx_failed", f"{spec.describe()} :: {exc!r}")
            self.log.probe(row)
            return row

        t_tx = time.perf_counter()
        post = self.drain(self.cfg.post_window, f"{phase}_post", index)

        novel = [m for m in post if not self.is_background(m)]
        row["pre_frames"] = len(pre)
        row["post_frames"] = len(post)
        row["novel_frames"] = len(novel)
        row["novel_ids"] = " | ".join(sorted({f"{m.arbitration_id:08X}" for m in novel}))
        row["novel_payloads"] = " || ".join(sorted({
            " ".join(f"{b:02X}" for b in m.data) for m in novel
        })[:6])
        row["error_frames"] = self.error_frames - errors_before

        if novel:
            lat = [(m.timestamp - t_tx) * 1000.0 if m.timestamp else None for m in novel]
            lat = [x for x in lat if x is not None and -1000 < x < 10_000]
            if lat:
                row["first_latency_ms"] = round(min(lat), 3)
                row["last_latency_ms"] = round(max(lat), 3)
            self.stats["responded"] += 1
            self.stats["novel_frames"] += len(novel)
            print(f"  [HIT] {spec.describe()}  -> {len(novel)} novel  "
                  f"ids={row['novel_ids']}")
        else:
            print(f"  [   ] {spec.describe()}")

        if self.cfg.prompt:
            try:
                row["operator_note"] = input("        operator note (enter to skip): ").strip()
            except EOFError:
                row["operator_note"] = ""

        self.stats["probes"] += 1
        self.log.probe(row)
        return row

    def run(self, specs: Iterable[ProbeSpec]) -> None:
        for index, spec in enumerate(specs, start=1):
            if self._abort:
                self.log.event("aborted", f"at probe {index}")
                break
            if (not self.cfg.ignore_errors
                    and self.error_frames >= self.cfg.error_abort_threshold):
                self.log.event("error_abort",
                               f"{self.error_frames} error frames >= threshold")
                print(f"[abort] {self.error_frames} CAN error frames -- "
                      f"check termination and topology before continuing.",
                      file=sys.stderr)
                break
            self.run_probe(index, spec)
            if self.cfg.send:
                time.sleep(self.cfg.gap)
        self.log.flush()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def hexint(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value, 16)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="DAB Active Driver Plus CAN probe harness (phase 4)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--interface", default=DEFAULT_INTERFACE)
    p.add_argument("--injector", default=DEFAULT_INJECTOR)
    p.add_argument("--observer", default=DEFAULT_OBSERVER)
    p.add_argument("--bitrate", type=int, default=DEFAULT_BITRATE)
    p.add_argument("--outdir", default=DEFAULT_OUTDIR)
    p.add_argument("--send", action="store_true",
                   help="ACTUALLY TRANSMIT. Without this the run is a dry enumeration.")
    p.add_argument("--baseline", type=float, default=15.0,
                   help="passive baseline seconds before probing (0 to skip)")
    p.add_argument("--pre-window", type=float, default=0.30)
    p.add_argument("--post-window", type=float, default=0.60)
    p.add_argument("--gap", type=float, default=0.40)
    p.add_argument("--repeats", type=int, default=1)
    p.add_argument("--prompt", action="store_true",
                   help="pause for an operator note after every probe")
    p.add_argument("--ignore-errors", action="store_true")

    sub = p.add_subparsers(dest="test", required=True)

    s = sub.add_parser("baseline", help="passive capture only, no injection")
    s.add_argument("--seconds", type=float, default=30.0)

    s = sub.add_parser("dlc-sweep", help="PRIORITY: sweep DLC 0..8 (never tested)")
    s.add_argument("--family", type=hexint, default=DEFAULT_FAMILY)
    s.add_argument("--token", type=hexint, default=DEFAULT_TOKEN)
    s.add_argument("--padding", nargs="+",
                   default=["truncate", "zero", "repeat"],
                   choices=["truncate", "zero", "repeat"])

    s = sub.add_parser("opcode-sweep", help="sweep payload byte 0 (function code)")
    s.add_argument("--family", type=hexint, default=DEFAULT_FAMILY)
    s.add_argument("--token", type=hexint, default=DEFAULT_TOKEN)
    s.add_argument("--dlc", type=int, default=8)
    s.add_argument("--lo", type=hexint, default=0x00)
    s.add_argument("--hi", type=hexint, default=0xFF)

    s = sub.add_parser("body-sweep", help="sweep payload bytes 1 and 2")
    s.add_argument("--family", type=hexint, default=DEFAULT_FAMILY)
    s.add_argument("--token", type=hexint, default=DEFAULT_TOKEN)
    s.add_argument("--dlc", type=int, default=5)

    s = sub.add_parser("idfield-sweep",
                       help="single-bit walk of the 29-bit id (no family/token assumption)")
    s.add_argument("--base-id", type=hexint, default=(DEFAULT_FAMILY << 16) | DEFAULT_TOKEN)
    s.add_argument("--token", type=hexint, default=DEFAULT_TOKEN)
    s.add_argument("--dlc", type=int, default=5)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    log = SessionLogger(test=args.test, outdir=Path(args.outdir))
    cfg = HarnessConfig(
        interface=args.interface,
        injector=args.injector,
        observer=args.observer,
        bitrate=args.bitrate,
        send=args.send,
        pre_window=args.pre_window,
        post_window=args.post_window,
        gap=args.gap,
        ignore_errors=args.ignore_errors,
        prompt=args.prompt,
    )

    log.meta({
        "script": Path(__file__).name,
        "argv": list(argv or sys.argv[1:]),
        "config": asdict(cfg),
        "files": log.manifest(),
        "rationale": (
            "Phase 4 sweeps request FORM (dlc, opcode, body, id bitfields). "
            "Phases 1-3 swept only the identifier while holding "
            "DLC=5 / payload=01 00 00 xx xx constant."
        ),
    })

    print(f"=== {args.test} / stamp {log.stamp} ===")
    print(f"    output : {log.outdir.resolve()}")
    print(f"    mode   : {'SEND (live injection)' if cfg.send else 'DRY-RUN (no TX)'}")

    harness = Harness(cfg, log)
    baseline_result = None
    try:
        if args.test == "baseline":
            harness.open()
            baseline_result = harness.baseline(args.seconds)
            specs: Iterable[ProbeSpec] = []
        else:
            harness.open()
            if args.baseline > 0:
                baseline_result = harness.baseline(args.baseline)
                if cfg.send:
                    time.sleep(cfg.settle)

            if args.test == "dlc-sweep":
                specs = gen_dlc_sweep(args.family, args.token,
                                      args.padding, args.repeats)
            elif args.test == "opcode-sweep":
                specs = gen_opcode_sweep(args.family, args.token, args.dlc,
                                         args.lo, args.hi, args.repeats)
            elif args.test == "body-sweep":
                specs = gen_body_sweep(args.family, args.token,
                                       args.dlc, args.repeats)
            elif args.test == "idfield-sweep":
                specs = gen_idfield_sweep(args.base_id, args.token,
                                          args.dlc, args.repeats)
            else:
                raise ValueError(f"unhandled test {args.test!r}")

            harness.run(specs)

    except Exception as exc:
        log.event("fatal_exception", repr(exc))
        print(f"[fatal] {exc!r}", file=sys.stderr)
        raise
    finally:
        harness.close()
        log.summary({
            "baseline": baseline_result,
            "stats": harness.stats,
            "error_frames": harness.error_frames,
            "aborted": harness._abort,
            "files": log.manifest(),
        })
        log.close()

    print(f"\n=== done ===")
    print(f"    probes    : {harness.stats['probes']}")
    print(f"    responded : {harness.stats['responded']}")
    print(f"    errors    : {harness.error_frames}")
    for kind in LOG_KINDS:
        ext = "json" if kind in ("meta", "summary") else "csv"
        print(f"    {kind:<8}: {log.path(kind, ext).name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
