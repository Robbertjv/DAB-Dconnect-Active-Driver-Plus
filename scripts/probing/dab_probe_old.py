#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dab_probe.py  --  DAB Active Driver Plus CAN request/response probe

Doel
----
Reproduceren en uitbreiden van de vondst uit Test_009.CSV (14-12-2025):

    Tx : 0x0012_C82D  DLC5  01 00 00 2D C8
    Rx : 0x103C_0481  DLC8  00 00 00 00 00 00 <var> 12   (~17x, 5 ms interval)
         0x103C_0401  DLC4  00 00 00 01
    latentie eerste respons: 9,3 ms

Het script kan:
  * de baseline verifieren (staat de 0x0001/0x0011 beacon erop?)
  * de bekend-werkende request herhalen (mode: verify)
  * een enkel token proberen (mode: single)
  * de volledige 16-bits tokenruimte aflopen (mode: sweep), hervatbaar

Alles wordt weggeschreven naar drie CSV's:
  <out>_raw.csv      elk frame, met richting en timestamp
  <out>_results.csv  een regel per geprobeerd token
  <out>_events.csv   elke beacon met marker != 0x03, gekoppeld aan het
                     token dat op dat moment werd geprobeerd

Afhankelijkheid:  pip install python-can
Hardware:         PEAK PCAN-USB, Windows 10

VEILIGHEID: dit praat met een live pompinverter. Draai de sweep bij voorkeur
met de pomp uitgeschakeld of droog. Wijzig de request-familie alleen als je
weet wat je doet -- 0x0012 gedroeg zich leesachtig, andere families niet
noodzakelijk.
"""

import argparse
import csv
import os
import random
import signal
import sys
import time
from datetime import datetime, timezone

try:
    import can
except ImportError:
    sys.exit("python-can ontbreekt.  Installeer met:  pip install python-can")


# ----------------------------------------------------------------------------
# Constanten afgeleid uit de traces
# ----------------------------------------------------------------------------

BEACON_FAMILIES = {0x0001, 0x0011}   # de continue 200 Hz announce van de unit
KNOWN_GOOD_TOKEN = 0xC82D            # token dat in Test_009 werkte
DEFAULT_REQ_FAMILY = 0x0012          # familie die in Test_009 respons gaf
MARKER_IDLE = 0x03                   # normale toestand in byte 4

MARKER_NAMES = {
    0x00: "init / adapter on-bus",
    0x03: "normaal, alleen op de bus",
    0x04: "transient event",
    0x05: "gezien tijdens DLC5-burst",
    0x06: "na busreset vanaf adapter",
}

_stop = False


def _sigint(_sig, _frm):
    global _stop
    _stop = True
    print("\n[!] Ctrl-C ontvangen, netjes afronden...")


signal.signal(signal.SIGINT, _sigint)


# ----------------------------------------------------------------------------
# Hulpfuncties
# ----------------------------------------------------------------------------

def family_of(can_id: int) -> int:
    """Bovenste 13 bits van een 29-bits ID, zoals gebruikt in de traces."""
    return (can_id >> 16) & 0x1FFF


def token_of(can_id: int) -> int:
    return can_id & 0xFFFF


def is_beacon(can_id: int) -> bool:
    return family_of(can_id) in BEACON_FAMILIES


def build_request(family: int, token: int) -> can.Message:
    """
    Bouwt exact het frame dat in Test_009 werkte:
        ID   = (family << 16) | token          extended
        DLC  = 5
        data = 01 00 00 <token_lo> <token_hi>  (little-endian, zoals waargenomen)
    """
    can_id = ((family & 0x1FFF) << 16) | (token & 0xFFFF)
    data = bytes([0x01, 0x00, 0x00, token & 0xFF, (token >> 8) & 0xFF])
    return can.Message(arbitration_id=can_id, data=data, is_extended_id=True)


def hexdata(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------

class Logger:
    def __init__(self, prefix: str):
        self.raw_path = f"{prefix}_raw.csv"
        self.res_path = f"{prefix}_results.csv"
        self.evt_path = f"{prefix}_events.csv"

        self.raw = self._open(self.raw_path, [
            "utc", "t_mono", "dir", "can_id_hex", "family_hex",
            "token_hex", "dlc", "data_hex", "probe_token_hex",
        ])
        self.res = self._open(self.res_path, [
            "utc", "probe_family_hex", "probe_token_hex", "tx_ok",
            "n_novel_frames", "first_latency_ms", "response_ids",
            "distinct_payloads", "payload_sample",
        ])
        self.evt = self._open(self.evt_path, [
            "utc", "t_mono", "can_id_hex", "marker_hex", "marker_name",
            "data_hex", "probe_token_hex",
        ])

    @staticmethod
    def _open(path, header):
        exists = os.path.exists(path) and os.path.getsize(path) > 0
        fh = open(path, "a", newline="", encoding="utf-8")
        wr = csv.writer(fh)
        if not exists:
            wr.writerow(header)
            fh.flush()
        return fh, wr

    def frame(self, direction, msg, probe_token):
        fh, wr = self.raw
        wr.writerow([
            utcnow(), f"{msg.timestamp:.6f}", direction,
            f"{msg.arbitration_id:08X}", f"{family_of(msg.arbitration_id):04X}",
            f"{token_of(msg.arbitration_id):04X}", msg.dlc,
            hexdata(msg.data),
            "" if probe_token is None else f"{probe_token:04X}",
        ])
        fh.flush()

    def event(self, msg, marker, probe_token):
        fh, wr = self.evt
        wr.writerow([
            utcnow(), f"{msg.timestamp:.6f}", f"{msg.arbitration_id:08X}",
            f"{marker:02X}", MARKER_NAMES.get(marker, "onbekend"),
            hexdata(msg.data),
            "" if probe_token is None else f"{probe_token:04X}",
        ])
        fh.flush()

    def result(self, family, token, tx_ok, novel, latency_ms):
        fh, wr = self.res
        ids = sorted({f"{m.arbitration_id:08X}" for m in novel})
        payloads = sorted({hexdata(m.data) for m in novel})
        wr.writerow([
            utcnow(), f"{family:04X}", f"{token:04X}", int(tx_ok),
            len(novel),
            "" if latency_ms is None else f"{latency_ms:.2f}",
            "|".join(ids[:8]),
            len(payloads),
            payloads[0] if payloads else "",
        ])
        fh.flush()

    def done_tokens(self, family):
        """Voor hervatten: welke tokens zijn al geprobeerd voor deze familie?"""
        done = set()
        if not os.path.exists(self.res_path):
            return done
        with open(self.res_path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                if row.get("probe_family_hex", "").upper() == f"{family:04X}":
                    try:
                        done.add(int(row["probe_token_hex"], 16))
                    except (KeyError, ValueError):
                        pass
        return done

    def close(self):
        for fh, _ in (self.raw, self.res, self.evt):
            fh.close()


# ----------------------------------------------------------------------------
# Kern: een enkele probe
# ----------------------------------------------------------------------------

def collect(bus, logger, duration_s, probe_token, quiet_extend_s=0.0):
    """
    Leest frames gedurende duration_s. Als quiet_extend_s > 0, wordt het venster
    telkens verlengd zolang er nieuwe niet-beacon frames binnenkomen -- zo vang
    je een hele burst, ook als die langer duurt dan verwacht.
    Geeft (novel_frames, t_first_novel_mono) terug.
    """
    novel = []
    t_start = time.monotonic()
    deadline = t_start + duration_s
    t_first = None

    while time.monotonic() < deadline and not _stop:
        msg = bus.recv(timeout=0.02)
        if msg is None:
            continue

        logger.frame("RX", msg, probe_token)

        if is_beacon(msg.arbitration_id):
            # marker zit in byte 4 van het lange (DLC7) frame
            if msg.dlc == 7 and len(msg.data) >= 5:
                marker = msg.data[4]
                if marker != MARKER_IDLE:
                    logger.event(msg, marker, probe_token)
                    print(f"      [marker {marker:02X}] "
                          f"{MARKER_NAMES.get(marker, 'onbekend')}")
            continue

        # alles wat geen beacon is, is interessant
        novel.append(msg)
        if t_first is None:
            t_first = time.monotonic()
        if quiet_extend_s:
            deadline = max(deadline, time.monotonic() + quiet_extend_s)

    return novel, t_first


def probe_token(bus, logger, family, token, window_s, quiet_s, settle_s):
    """Stuurt een request en vangt de respons. Geeft (novel, latency_ms) terug."""
    # bus even laten leeglopen zodat een vorige burst niet meetelt
    t_end = time.monotonic() + settle_s
    while time.monotonic() < t_end and not _stop:
        m = bus.recv(timeout=0.01)
        if m is not None:
            logger.frame("RX", m, None)

    msg = build_request(family, token)
    tx_ok = True
    t_tx = time.monotonic()
    try:
        bus.send(msg)
        msg.timestamp = t_tx
        logger.frame("TX", msg, token)
    except can.CanError as exc:
        tx_ok = False
        print(f"      [!] TX mislukt: {exc}")

    novel, t_first = collect(bus, logger, window_s, token, quiet_extend_s=quiet_s)
    latency_ms = None if t_first is None else (t_first - t_tx) * 1000.0
    logger.result(family, token, tx_ok, novel, latency_ms)
    return novel, latency_ms


# ----------------------------------------------------------------------------
# Modes
# ----------------------------------------------------------------------------

def mode_baseline(bus, logger, seconds):
    print(f"[*] Baseline luisteren, {seconds} s ...")
    novel, _ = collect(bus, logger, seconds, None)
    print(f"[*] Niet-beacon frames tijdens baseline: {len(novel)}")
    if novel:
        print("    LET OP: er staat ander verkeer op de bus dan de beacon.")
        for m in novel[:10]:
            print(f"    {m.arbitration_id:08X}  DLC{m.dlc}  {hexdata(m.data)}")
    else:
        print("    Alleen de 0x0001/0x0011 beacon. Zoals verwacht.")


def mode_verify(bus, logger, family, repeats, interval_s, window_s, quiet_s, settle_s):
    print(f"[*] VERIFY: familie {family:04X}, token {KNOWN_GOOD_TOKEN:04X}, "
          f"{repeats}x met {interval_s} s tussenpoos")
    hits = 0
    lats = []
    for i in range(1, repeats + 1):
        if _stop:
            break
        novel, lat = probe_token(bus, logger, family, KNOWN_GOOD_TOKEN,
                                 window_s, quiet_s, settle_s)
        if novel:
            hits += 1
            lats.append(lat)
            ids = sorted({f"{m.arbitration_id:08X}" for m in novel})
            print(f"    {i:3d}/{repeats}  HIT  {len(novel):3d} frames  "
                  f"latentie {lat:6.2f} ms  ids={','.join(ids[:4])}")
        else:
            print(f"    {i:3d}/{repeats}  --   geen respons")
        rest = interval_s - window_s - settle_s
        if rest > 0 and not _stop:
            time.sleep(rest)

    print(f"\n[*] Resultaat: {hits}/{repeats} requests beantwoord.")
    if lats:
        print(f"    latentie  min {min(lats):.2f}  gem {sum(lats)/len(lats):.2f}  "
              f"max {max(lats):.2f} ms   (Test_009 gaf 9,3 ms)")
    if hits == 0:
        print("    Niets terug. Controleer bitrate, bedrading en of de unit "
              "in dezelfde toestand staat als in december.")


def mode_single(bus, logger, family, token, window_s, quiet_s, settle_s):
    print(f"[*] SINGLE: familie {family:04X}, token {token:04X}")
    novel, lat = probe_token(bus, logger, family, token, window_s, quiet_s, settle_s)
    if not novel:
        print("    Geen respons.")
        return
    print(f"    {len(novel)} frames, eerste na {lat:.2f} ms")
    seen = {}
    for m in novel:
        seen.setdefault(m.arbitration_id, []).append(hexdata(m.data))
    for cid, payloads in sorted(seen.items()):
        uniq = sorted(set(payloads))
        print(f"    {cid:08X}  n={len(payloads):3d}  uniek={len(uniq)}")
        for p in uniq[:6]:
            print(f"        {p}")


def mode_sweep(bus, logger, family, start, end, order, window_s, quiet_s,
               settle_s, stop_on_hit, resume):
    tokens = list(range(start, end + 1))
    if resume:
        done = logger.done_tokens(family)
        before = len(tokens)
        tokens = [t for t in tokens if t not in done]
        print(f"[*] Hervatten: {before - len(tokens)} tokens al gedaan, "
              f"{len(tokens)} te gaan.")
    if order == "random":
        random.shuffle(tokens)

    per = window_s + settle_s
    print(f"[*] SWEEP familie {family:04X}: {len(tokens)} tokens, "
          f"~{per:.2f} s per token  ->  geschat {len(tokens) * per / 3600:.2f} uur")
    print("[*] Ctrl-C stopt netjes; met --resume pak je later de draad op.\n")

    hits = 0
    t0 = time.monotonic()
    for i, tok in enumerate(tokens, 1):
        if _stop:
            break
        novel, lat = probe_token(bus, logger, family, tok, window_s, quiet_s, settle_s)
        if novel:
            hits += 1
            ids = sorted({f"{m.arbitration_id:08X}" for m in novel})
            print(f"  >>> HIT token {tok:04X}: {len(novel)} frames, "
                  f"{lat:.2f} ms, ids={','.join(ids[:4])}")
            if stop_on_hit:
                print("      --stop-on-hit actief, sweep gestopt.")
                break
        if i % 50 == 0 or i == len(tokens):
            el = time.monotonic() - t0
            rate = i / el if el else 0
            eta = (len(tokens) - i) / rate / 60 if rate else 0
            print(f"  [{i}/{len(tokens)}] hits={hits}  "
                  f"{rate * 60:.0f} tokens/min  ETA {eta:.0f} min")

    print(f"\n[*] Sweep afgerond of onderbroken. Hits: {hits}")


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="DAB Active Driver Plus CAN request/response probe",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    ap.add_argument("--mode", required=True,
                    choices=["baseline", "verify", "single", "sweep"])
    ap.add_argument("--channel", default="PCAN_USBBUS1")
    ap.add_argument("--bitrate", type=int, default=1000000,
                    help="uit de traces afgeleid op ~991 kbit/s; verifieer dit")
    ap.add_argument("--out", default="dab_probe",
                    help="prefix voor de CSV-bestanden")

    ap.add_argument("--family", type=lambda s: int(s, 0), default=DEFAULT_REQ_FAMILY,
                    help="request-familie, hex toegestaan (0x0012 werkte)")
    ap.add_argument("--token", type=lambda s: int(s, 0), default=KNOWN_GOOD_TOKEN,
                    help="token voor mode=single")

    ap.add_argument("--window", type=float, default=0.25,
                    help="luistervenster na de request, seconden")
    ap.add_argument("--quiet", type=float, default=0.05,
                    help="venster verlengen zolang responsframes blijven komen")
    ap.add_argument("--settle", type=float, default=0.05,
                    help="bus leeg laten lopen voor de request")

    ap.add_argument("--baseline-seconds", type=float, default=10.0)
    ap.add_argument("--repeats", type=int, default=20, help="mode=verify")
    ap.add_argument("--interval", type=float, default=5.0,
                    help="tussenpoos in mode=verify (Test_009 gebruikte 5 s)")

    ap.add_argument("--start", type=lambda s: int(s, 0), default=0x0000)
    ap.add_argument("--end", type=lambda s: int(s, 0), default=0xFFFF)
    ap.add_argument("--order", choices=["sequential", "random"], default="sequential")
    ap.add_argument("--stop-on-hit", action="store_true")
    ap.add_argument("--resume", action="store_true")

    args = ap.parse_args()

    print("=" * 74)
    print(f" DAB probe  |  {utcnow()}")
    print(f" kanaal {args.channel}  bitrate {args.bitrate}  "
          f"familie 0x{args.family:04X}")
    print("=" * 74)

    logger = Logger(args.out)
    bus = None
    try:
        try:
            bus = can.Bus(interface="pcan", channel=args.channel,
                          bitrate=args.bitrate, receive_own_messages=False)
        except TypeError:   # oudere python-can
            bus = can.interface.Bus(bustype="pcan", channel=args.channel,
                                    bitrate=args.bitrate)

        if args.mode == "baseline":
            mode_baseline(bus, logger, args.baseline_seconds)
        elif args.mode == "verify":
            mode_verify(bus, logger, args.family, args.repeats, args.interval,
                        args.window, args.quiet, args.settle)
        elif args.mode == "single":
            mode_single(bus, logger, args.family, args.token,
                        args.window, args.quiet, args.settle)
        elif args.mode == "sweep":
            mode_sweep(bus, logger, args.family, args.start, args.end, args.order,
                       args.window, args.quiet, args.settle,
                       args.stop_on_hit, args.resume)

    finally:
        if bus is not None:
            bus.shutdown()
        logger.close()
        print(f"\n[*] Logs weggeschreven naar {args.out}_raw.csv, "
              f"{args.out}_results.csv, {args.out}_events.csv")


if __name__ == "__main__":
    main()
