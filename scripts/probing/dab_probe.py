#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dab_probe.py  --  DAB Active Driver Plus CAN request/response probe   (v2)

Doel
----
Reproduceren en uitbreiden van de vondst uit Test_009.CSV (14-12-2025):

    Tx : 0x0012_C82D  DLC5  01 00 00 2D C8
    Rx : 0x103C_0481  DLC8  00 00 00 00 00 00 <var> 12     17x
         0x103C_0401  DLC4  00 00 00 01                    17x
    eerste respons na 8,2 - 12,7 ms, burst duurt ~80 ms, exact 34 frames

Let op: 0xC82D is geen betekenisvolle identifier. Het is een van de
willekeurige tokens die de unit zelf uitzond in Test_001 en Test_003.
De trigger zit vrijwel zeker in het FAMILIE-veld (0x0012), niet in het token.

Modes
-----
  baseline   luisteren, controleren of de bitrate klopt
  verify     het bekend-werkende verzoek herhalen
  single     een enkel token proberen
  tokens     een lijstje tokens achter elkaar proberen
  sweep      de hele 16-bits tokenruimte aflopen, hervatbaar

Uitvoer
-------
  <out>_raw.csv      elk frame (beacon optioneel weg te filteren)
  <out>_results.csv  een regel per geprobeerd token
  <out>_events.csv   elke beacon met marker != 0x03, met het token dat
                     op dat moment werd geprobeerd

Afhankelijkheid:  pip install python-can
Hardware:         PEAK PCAN-USB, Windows 10

VEILIGHEID: dit praat met een live pompinverter. Draai lange sessies bij
voorkeur met de pomp uitgeschakeld of droog. Wijzig de request-familie
alleen bewust -- 0x0012 gedroeg zich leesachtig, andere families niet
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
# Constanten, afgeleid uit de traces
# ----------------------------------------------------------------------------

BEACON_FAMILIES = {0x0001, 0x0011}   # de continue 200 Hz announce van de unit
KNOWN_GOOD_TOKEN = 0xC82D            # token dat in Test_009 respons gaf
DEFAULT_REQ_FAMILY = 0x0012          # familie die in Test_009 respons gaf
MARKER_IDLE = 0x03                   # normale toestand in byte 4
FLUSH_EVERY = 200                    # raw-log niet bij elk frame flushen

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
        data = 01 00 00 <token_lo> <token_hi>  little-endian, zoals waargenomen
    """
    can_id = ((family & 0x1FFF) << 16) | (token & 0xFFFF)
    data = bytes([0x01, 0x00, 0x00, token & 0xFF, (token >> 8) & 0xFF])
    return can.Message(arbitration_id=can_id, data=data, is_extended_id=True)


def hexdata(data) -> str:
    return " ".join(f"{b:02X}" for b in data)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def parse_int(s: str) -> int:
    """Accepteert 0x1234, 1234 (decimaal) en 1234h."""
    s = s.strip()
    if s.lower().endswith("h"):
        return int(s[:-1], 16)
    return int(s, 0)


# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------

class Logger:
    def __init__(self, prefix: str, log_beacon: bool = True):
        self.log_beacon = log_beacon
        self._n = 0

        self.raw_path = f"{prefix}_raw.csv"
        self.res_path = f"{prefix}_results.csv"
        self.evt_path = f"{prefix}_events.csv"

        self.raw = self._open(self.raw_path, [
            "utc", "t_mono", "dir", "can_id_hex", "family_hex",
            "token_hex", "dlc", "data_hex", "probe_token_hex",
        ])
        self.res = self._open(self.res_path, [
            "utc", "probe_family_hex", "probe_token_hex", "tx_ok",
            "n_novel_frames", "first_latency_ms", "burst_ms",
            "response_ids", "distinct_payloads", "payload_sample",
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

    # ---- raw frames -------------------------------------------------------

    def frame(self, direction, msg, probe_tok):
        if not self.log_beacon and is_beacon(msg.arbitration_id):
            return
        fh, wr = self.raw
        wr.writerow([
            utcnow(), f"{msg.timestamp:.6f}", direction,
            f"{msg.arbitration_id:08X}", f"{family_of(msg.arbitration_id):04X}",
            f"{token_of(msg.arbitration_id):04X}", msg.dlc,
            hexdata(msg.data),
            "" if probe_tok is None else f"{probe_tok:04X}",
        ])
        self._n += 1
        if self._n % FLUSH_EVERY == 0:
            fh.flush()

    # ---- marker-events ----------------------------------------------------

    def event(self, msg, marker, probe_tok):
        fh, wr = self.evt
        wr.writerow([
            utcnow(), f"{msg.timestamp:.6f}", f"{msg.arbitration_id:08X}",
            f"{marker:02X}", MARKER_NAMES.get(marker, "onbekend"),
            hexdata(msg.data),
            "" if probe_tok is None else f"{probe_tok:04X}",
        ])
        fh.flush()

    # ---- resultaat per probe ---------------------------------------------

    def result(self, family, token, tx_ok, novel, latency_ms, burst_ms):
        fh, wr = self.res
        ids = sorted({f"{m.arbitration_id:08X}" for m in novel})
        payloads = sorted({hexdata(m.data) for m in novel})
        wr.writerow([
            utcnow(), f"{family:04X}", f"{token:04X}", int(tx_ok),
            len(novel),
            "" if latency_ms is None else f"{latency_ms:.2f}",
            "" if burst_ms is None else f"{burst_ms:.2f}",
            "|".join(ids[:8]),
            len(payloads),
            payloads[0] if payloads else "",
        ])
        fh.flush()

    # ---- hervatten --------------------------------------------------------

    def done_tokens(self, family):
        """Welke tokens zijn al geprobeerd voor deze familie?"""
        done = set()
        if not os.path.exists(self.res_path):
            return done
        with open(self.res_path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                if row.get("probe_family_hex", "").upper() == f"{family:04X}":
                    try:
                        done.add(int(row["probe_token_hex"], 16))
                    except (KeyError, TypeError, ValueError):
                        pass
        return done

    def close(self):
        for fh, _ in (self.raw, self.res, self.evt):
            try:
                fh.flush()
                fh.close()
            except Exception:
                pass


# ----------------------------------------------------------------------------
# Kern
# ----------------------------------------------------------------------------

def collect(bus, logger, duration_s, probe_tok, quiet_extend_s=0.0):
    """
    Leest frames gedurende duration_s. Met quiet_extend_s > 0 wordt het venster
    telkens verlengd zolang er nieuwe niet-beacon frames binnenkomen, zodat een
    burst nooit wordt afgekapt.
    Geeft (novel_frames, t_eerste_mono, t_laatste_mono) terug.
    """
    novel = []
    deadline = time.monotonic() + duration_s
    t_first = None
    t_last = None

    while time.monotonic() < deadline and not _stop:
        msg = bus.recv(timeout=0.02)
        if msg is None:
            continue

        logger.frame("RX", msg, probe_tok)

        if is_beacon(msg.arbitration_id):
            # marker zit in byte 4 van het lange (DLC7) frame
            if msg.dlc == 7 and len(msg.data) >= 5:
                marker = msg.data[4]
                if marker != MARKER_IDLE:
                    logger.event(msg, marker, probe_tok)
                    print(f"      [marker {marker:02X}] "
                          f"{MARKER_NAMES.get(marker, 'onbekend')}")
            continue

        novel.append(msg)
        now = time.monotonic()
        if t_first is None:
            t_first = now
        t_last = now
        if quiet_extend_s:
            deadline = max(deadline, now + quiet_extend_s)

    return novel, t_first, t_last


def drain(bus, logger, seconds):
    """Bus even leeg laten lopen zodat een vorige burst niet meetelt."""
    t_end = time.monotonic() + seconds
    while time.monotonic() < t_end and not _stop:
        m = bus.recv(timeout=0.01)
        if m is not None:
            logger.frame("RX", m, None)


def do_probe(bus, logger, family, token, window_s, quiet_s, settle_s):
    """Stuurt een request en vangt de respons. Geeft (novel, latency, burst) terug."""
    drain(bus, logger, settle_s)

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

    novel, t_first, t_last = collect(bus, logger, window_s, token,
                                     quiet_extend_s=quiet_s)
    latency_ms = None if t_first is None else (t_first - t_tx) * 1000.0
    burst_ms = None if t_first is None else (t_last - t_first) * 1000.0
    logger.result(family, token, tx_ok, novel, latency_ms, burst_ms)
    return novel, latency_ms, burst_ms


def describe(novel, latency_ms, burst_ms, indent="    "):
    """Vat een respons samen op het scherm."""
    if not novel:
        print(f"{indent}geen respons")
        return
    print(f"{indent}{len(novel)} frames, eerste na {latency_ms:.2f} ms, "
          f"burst {burst_ms:.1f} ms")
    per_id = {}
    for m in novel:
        per_id.setdefault(m.arbitration_id, []).append(hexdata(m.data))
    for cid, payloads in sorted(per_id.items()):
        uniek = sorted(set(payloads))
        print(f"{indent}  {cid:08X}  n={len(payloads):3d}  uniek={len(uniek)}")
        for p in uniek[:6]:
            print(f"{indent}      {p}")
        if len(uniek) > 6:
            print(f"{indent}      ... en {len(uniek) - 6} andere")


# ----------------------------------------------------------------------------
# Modes
# ----------------------------------------------------------------------------

def mode_baseline(bus, logger, seconds):
    print(f"[*] Baseline luisteren, {seconds:.0f} s ...")
    n_beacon = 0
    novel = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and not _stop:
        msg = bus.recv(timeout=0.02)
        if msg is None:
            continue
        logger.frame("RX", msg, None)
        if is_beacon(msg.arbitration_id):
            n_beacon += 1
            if msg.dlc == 7 and len(msg.data) >= 5 and msg.data[4] != MARKER_IDLE:
                logger.event(msg, msg.data[4], None)
                print(f"    [marker {msg.data[4]:02X}] "
                      f"{MARKER_NAMES.get(msg.data[4], 'onbekend')}")
        else:
            novel.append(msg)

    print(f"[*] Beacon-frames : {n_beacon}  ({n_beacon / seconds:.0f} per seconde)")
    print(f"[*] Overige frames: {len(novel)}")

    if n_beacon == 0 and not novel:
        print("\n    GEEN VERKEER ONTVANGEN.")
        print("    Controleer in deze volgorde: bitrate, kanaalnaam,")
        print("    bekabeling/terminatie, en of de unit aan staat.")
    elif n_beacon and abs(n_beacon / seconds - 400) > 120:
        print("\n    Let op: verwacht was ~400 frames/s (200 paren).")
        print("    Wijkt dit sterk af, controleer dan de bitrate.")
    if novel:
        print("\n    Er staat ander verkeer op de bus dan de beacon:")
        for m in novel[:10]:
            print(f"      {m.arbitration_id:08X}  DLC{m.dlc}  {hexdata(m.data)}")


def mode_verify(bus, logger, family, token, repeats, interval_s,
                window_s, quiet_s, settle_s):
    print(f"[*] VERIFY: familie {family:04X}, token {token:04X}, "
          f"{repeats}x met {interval_s:.1f} s tussenpoos")
    print("    Verwacht (Test_009): 34 frames, eerste na ~9 ms, burst ~80 ms\n")
    hits, lats = 0, []
    for i in range(1, repeats + 1):
        if _stop:
            break
        novel, lat, burst = do_probe(bus, logger, family, token,
                                     window_s, quiet_s, settle_s)
        if novel:
            hits += 1
            lats.append(lat)
            ids = sorted({f"{m.arbitration_id:08X}" for m in novel})
            print(f"    {i:3d}/{repeats}  HIT  {len(novel):3d} frames  "
                  f"{lat:6.2f} ms  burst {burst:5.1f} ms  {','.join(ids[:4])}")
        else:
            print(f"    {i:3d}/{repeats}  --   geen respons")
        rest = interval_s - window_s - settle_s
        if rest > 0 and not _stop:
            time.sleep(rest)

    print(f"\n[*] Resultaat: {hits}/{repeats} verzoeken beantwoord.")
    if lats:
        print(f"    latentie  min {min(lats):.2f}  gem {sum(lats)/len(lats):.2f}  "
              f"max {max(lats):.2f} ms   (Test_009 gaf 8,2 - 12,7 ms)")
    else:
        print("    Niets terug. Controleer bitrate en bedrading, en of de unit")
        print("    in dezelfde toestand staat als op 14 december.")


def mode_single(bus, logger, family, token, window_s, quiet_s, settle_s):
    print(f"[*] SINGLE: familie {family:04X}, token {token:04X}")
    novel, lat, burst = do_probe(bus, logger, family, token,
                                 window_s, quiet_s, settle_s)
    describe(novel, lat, burst)


def mode_tokens(bus, logger, family, tokens, window_s, quiet_s, settle_s):
    print(f"[*] TOKENS: familie {family:04X}, "
          f"{len(tokens)} tokens: {', '.join(f'{t:04X}' for t in tokens)}\n")
    hits = 0
    for tok in tokens:
        if _stop:
            break
        print(f"  token {tok:04X}")
        novel, lat, burst = do_probe(bus, logger, family, tok,
                                     window_s, quiet_s, settle_s)
        describe(novel, lat, burst, indent="      ")
        if novel:
            hits += 1

    print(f"\n[*] {hits}/{len(tokens)} tokens gaven respons.")
    if hits == len(tokens) and hits > 1:
        print("    Alle tokens antwoorden -> het token is betekenisloos en de")
        print("    trigger zit in het familieveld. Een volledige sweep heeft")
        print("    dan geen zin; verken in plaats daarvan 0x0013, 0x0014, 0x0022.")
    elif hits == 0:
        print("    Geen enkel token antwoordt. Draai eerst --mode verify.")
    else:
        print("    Selectieve respons -> het token draagt wel betekenis.")
        print("    Een sweep is dan wel zinvol.")


def mode_sweep(bus, logger, family, start, end, order, window_s, quiet_s,
               settle_s, stop_on_hit, resume):
    tokens = list(range(start, end + 1))
    if resume:
        done = logger.done_tokens(family)
        before = len(tokens)
        tokens = [t for t in tokens if t not in done]
        print(f"[*] Hervatten: {before - len(tokens)} al gedaan, "
              f"{len(tokens)} te gaan.")
    if order == "random":
        random.shuffle(tokens)

    per = window_s + settle_s
    print(f"[*] SWEEP familie {family:04X}: {len(tokens)} tokens, "
          f"~{per:.2f} s per token -> geschat {len(tokens) * per / 3600:.2f} uur")
    print("[*] Ctrl-C stopt netjes; met --resume pak je de draad later op.\n")

    hits = 0
    t0 = time.monotonic()
    for i, tok in enumerate(tokens, 1):
        if _stop:
            break
        novel, lat, burst = do_probe(bus, logger, family, tok,
                                     window_s, quiet_s, settle_s)
        if novel:
            hits += 1
            ids = sorted({f"{m.arbitration_id:08X}" for m in novel})
            print(f"  >>> HIT {tok:04X}: {len(novel)} frames, {lat:.2f} ms, "
                  f"{','.join(ids[:4])}")
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

def open_bus(channel, bitrate):
    """python-can 4.x gebruikt interface=, oudere versies bustype=."""
    try:
        return can.Bus(interface="pcan", channel=channel,
                       bitrate=bitrate, receive_own_messages=False)
    except TypeError:
        return can.interface.Bus(bustype="pcan", channel=channel,
                                 bitrate=bitrate)


def main():
    ap = argparse.ArgumentParser(
        description="DAB Active Driver Plus CAN request/response probe",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    ap.add_argument("--mode", required=True,
                    choices=["baseline", "verify", "single", "tokens", "sweep"])
    ap.add_argument("--channel", default="PCAN_USBBUS1")
    ap.add_argument("--bitrate", type=int, default=1000000,
                    help="uit de traces afgeleid op ~991 kbit/s; verifieer dit")
    ap.add_argument("--out", default="dab_probe",
                    help="prefix voor de CSV-bestanden")
    ap.add_argument("--no-raw-beacon", action="store_true",
                    help="beacon niet naar de raw-log schrijven (aanraden bij sweep)")

    ap.add_argument("--family", type=parse_int, default=DEFAULT_REQ_FAMILY,
                    help="request-familie; 0x0012 gaf respons in Test_009")
    ap.add_argument("--token", type=parse_int, default=KNOWN_GOOD_TOKEN,
                    help="token voor mode=single en mode=verify")
    ap.add_argument("--tokens", default="0x0001,0x8000,0xFFFF",
                    help="kommagescheiden lijst voor mode=tokens")

    ap.add_argument("--window", type=float, default=0.25,
                    help="luistervenster na de request, seconden")
    ap.add_argument("--quiet", type=float, default=0.05,
                    help="venster verlengen zolang responsframes blijven komen")
    ap.add_argument("--settle", type=float, default=0.05,
                    help="bus leeg laten lopen voor de request")

    ap.add_argument("--baseline-seconds", type=float, default=10.0)
    ap.add_argument("--repeats", type=int, default=20, help="mode=verify")
    ap.add_argument("--interval", type=float, default=5.0,
                    help="tussenpoos bij verify; Test_009 gebruikte 5 s")

    ap.add_argument("--start", type=parse_int, default=0x0000)
    ap.add_argument("--end", type=parse_int, default=0xFFFF)
    ap.add_argument("--order", choices=["sequential", "random"],
                    default="sequential")
    ap.add_argument("--stop-on-hit", action="store_true")
    ap.add_argument("--resume", action="store_true")

    args = ap.parse_args()

    print("=" * 74)
    print(f" DAB probe v2  |  {utcnow()}")
    print(f" kanaal {args.channel}   bitrate {args.bitrate}   "
          f"familie 0x{args.family:04X}")
    print(f" raw-log beacon: {'nee' if args.no_raw_beacon else 'ja'}")
    print("=" * 74)

    logger = Logger(args.out, log_beacon=not args.no_raw_beacon)
    bus = None
    try:
        try:
            bus = open_bus(args.channel, args.bitrate)
        except Exception as exc:
            print(f"\n[!] Kan de CAN-bus niet openen: {exc}")
            print("    Controleer of PCAN-View gesloten is (het kanaal kan")
            print("    maar door een applicatie tegelijk worden gebruikt),")
            print("    en of de kanaalnaam klopt (PCAN_USBBUS1, PCAN_USBBUS2, ...).")
            return 2

        if args.mode == "baseline":
            mode_baseline(bus, logger, args.baseline_seconds)
        elif args.mode == "verify":
            mode_verify(bus, logger, args.family, args.token, args.repeats,
                        args.interval, args.window, args.quiet, args.settle)
        elif args.mode == "single":
            mode_single(bus, logger, args.family, args.token,
                        args.window, args.quiet, args.settle)
        elif args.mode == "tokens":
            toks = [parse_int(t) for t in args.tokens.split(",") if t.strip()]
            mode_tokens(bus, logger, args.family, toks,
                        args.window, args.quiet, args.settle)
        elif args.mode == "sweep":
            mode_sweep(bus, logger, args.family, args.start, args.end,
                       args.order, args.window, args.quiet, args.settle,
                       args.stop_on_hit, args.resume)
        return 0

    finally:
        if bus is not None:
            try:
                bus.shutdown()
            except Exception:
                pass
        logger.close()
        print(f"\n[*] Logs: {args.out}_raw.csv, {args.out}_results.csv, "
              f"{args.out}_events.csv")


if __name__ == "__main__":
    sys.exit(main())
