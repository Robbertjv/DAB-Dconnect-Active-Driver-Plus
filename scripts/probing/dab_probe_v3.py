#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dab_probe.py -- DAB Active Driver Plus CAN request/response probe (v3)

Wijzigingen ten opzichte van v2
--------------------------------
* Een baseline-model bepaalt normaal aanwezig verkeer.
* Niet ieder niet-beaconframe wordt automatisch een response genoemd.
* Alle ontvangen velden worden op het probe-token onderzocht:
  - payload big-endian: C8 2D
  - payload byte-swapped/little-endian: 2D C8
  - onderste 16 bits van de CAN-ID, exact en byte-swapped
* Iedere kandidaat-response krijgt latency, baseline-rate en reden.
* AD wordt per probe geregistreerd. Bij resultaten van verschillende
  AD-instellingen wordt alleen een voorzichtige ID/DLC-vergelijking gegeven.
* Beaconframes worden niet meer blind overgeslagen: markerwijzigingen,
  tokenrelaties en afwijkende rates kunnen alsnog kandidaat-responses zijn.

Uitvoer
-------
<out>_raw.csv        alle gelogde RX/TX-frames
<out>_results.csv    één samenvatting per probe
<out>_responses.csv  één regel per response-ID/DLC-groep per probe
<out>_events.csv     beacon-marker-events
<out>_baseline.csv   samenvatting van het baseline-model

Afhankelijkheid: pip install python-can
Hardware: PEAK PCAN-USB, Windows 10

VEILIGHEID
----------
Dit script zendt naar een live pompinverter. Gebruik actieve modi alleen in een
veilige testopstelling. Een succesvolle CAN-transmissie bewijst alleen dat het
frame op de bus is gezet; niet dat het apparaat het als geldig verzoek heeft
geaccepteerd.
"""

import argparse
import csv
import math
import os
import random
import signal
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone

try:
    import can
except ImportError:
    sys.exit("python-can ontbreekt. Installeer met: pip install python-can")


VERSION = "3.0"
BEACON_FAMILIES = {0x0001, 0x0011}
KNOWN_GOOD_TOKEN = 0xC82D
DEFAULT_REQ_FAMILY = 0x0012
MARKER_IDLE = 0x03
FLUSH_EVERY = 200

# Een family met veel verschillende low-16 ID's is waarschijnlijk dynamisch.
DYNAMIC_MIN_FRAMES = 20
DYNAMIC_UNIQUE_RATIO = 0.20

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


# ---------------------------------------------------------------------------
# Basisfuncties
# ---------------------------------------------------------------------------

def family_of(can_id: int) -> int:
    return (can_id >> 16) & 0x1FFF


def token_of(can_id: int) -> int:
    return can_id & 0xFFFF


def byteswap16(value: int) -> int:
    value &= 0xFFFF
    return ((value & 0xFF) << 8) | ((value >> 8) & 0xFF)


def is_beacon(can_id: int) -> bool:
    return family_of(can_id) in BEACON_FAMILIES


def build_request(family: int, token: int) -> can.Message:
    can_id = ((family & 0x1FFF) << 16) | (token & 0xFFFF)
    data = bytes([0x01, 0x00, 0x00, token & 0xFF, (token >> 8) & 0xFF])
    return can.Message(
        arbitration_id=can_id,
        data=data,
        is_extended_id=True,
    )


def hexdata(data) -> str:
    return " ".join(f"{b:02X}" for b in data)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def parse_int(text: str) -> int:
    text = text.strip()
    if text.lower().endswith("h"):
        return int(text[:-1], 16)
    return int(text, 0)


def marker_of(msg):
    if family_of(msg.arbitration_id) == 0x0001 and msg.dlc == 7 and len(msg.data) >= 5:
        return msg.data[4]
    return None


def safe_rate(count: int, seconds: float) -> float:
    return count / seconds if seconds > 0 else 0.0


def count_threshold(expected: float, sigma: float, min_excess: int) -> int:
    """Conservatieve Poisson-achtige drempel voor activiteit boven baseline."""
    return max(
        min_excess,
        int(math.ceil(expected + sigma * math.sqrt(expected + 1.0))),
    )


# ---------------------------------------------------------------------------
# Interne records
# ---------------------------------------------------------------------------

@dataclass
class CapturedFrame:
    msg: object
    host_mono: float
    latency_ms: float


@dataclass
class TokenRelation:
    exact_present: bool
    swapped_present: bool
    id_exact: bool
    id_swapped: bool
    locations: list


@dataclass
class ResponseGroup:
    can_id: int
    dlc: int
    frames: list
    baseline_count: int
    baseline_rate_hz: float
    expected_count: float
    threshold_count: int
    family_dynamic: bool
    new_payload_count: int
    reasons: list
    candidate: bool
    relation: TokenRelation

    @property
    def first_latency_ms(self):
        return min(f.latency_ms for f in self.frames)

    @property
    def last_latency_ms(self):
        return max(f.latency_ms for f in self.frames)

    @property
    def payloads(self):
        return sorted({hexdata(f.msg.data) for f in self.frames})


@dataclass
class ProbeAnalysis:
    groups: list
    candidates: list
    all_frames: list
    capture_duration_s: float

    @property
    def response(self):
        return bool(self.candidates)

    @property
    def first_latency_ms(self):
        if not self.candidates:
            return None
        return min(g.first_latency_ms for g in self.candidates)

    @property
    def last_latency_ms(self):
        if not self.candidates:
            return None
        return max(g.last_latency_ms for g in self.candidates)

    @property
    def burst_ms(self):
        if not self.candidates:
            return None
        return self.last_latency_ms - self.first_latency_ms

    @property
    def exact_present(self):
        return any(g.relation.exact_present for g in self.candidates)

    @property
    def swapped_present(self):
        return any(g.relation.swapped_present for g in self.candidates)

    @property
    def id_relation(self):
        labels = set()
        for group in self.candidates:
            if group.relation.id_exact:
                labels.add("id_low16_exact")
            if group.relation.id_swapped:
                labels.add("id_low16_swapped")
        return "|".join(sorted(labels)) if labels else "none"

    @property
    def signature(self):
        return "|".join(
            f"{g.can_id:08X}/DLC{g.dlc}"
            for g in sorted(self.candidates, key=lambda x: (x.can_id, x.dlc))
        )


# ---------------------------------------------------------------------------
# Tokenanalyse
# ---------------------------------------------------------------------------

def find_token_relation(msg, probe_token: int) -> TokenRelation:
    """
    Exact betekent de numerieke tokenvolgorde in big-endian bytes.
    Voor C82D:
        exact   = C8 2D
        swapped = 2D C8

    De request zelf gebruikt de swapped/little-endian vorm 2D C8.
    Payloadmatches worden op iedere byte-offset gezocht.
    """
    token = probe_token & 0xFFFF
    exact_bytes = bytes([(token >> 8) & 0xFF, token & 0xFF])
    swapped_bytes = bytes([token & 0xFF, (token >> 8) & 0xFF])
    payload = bytes(msg.data)
    locations = []

    exact_payload = False
    swapped_payload = False

    for offset in range(max(0, len(payload) - 1)):
        word = payload[offset:offset + 2]
        if word == exact_bytes:
            exact_payload = True
            locations.append(f"payload[{offset}:{offset + 2}]=exact_be")
        if word == swapped_bytes:
            swapped_payload = True
            locations.append(f"payload[{offset}:{offset + 2}]=swapped_le")

    low16 = token_of(msg.arbitration_id)
    id_exact = low16 == token
    id_swapped = low16 == byteswap16(token)

    if id_exact:
        locations.append("can_id_low16=exact")
    if id_swapped:
        locations.append("can_id_low16=swapped")

    return TokenRelation(
        exact_present=exact_payload or id_exact,
        swapped_present=swapped_payload or id_swapped,
        id_exact=id_exact,
        id_swapped=id_swapped,
        locations=locations,
    )


def is_probable_own_echo(msg, request, latency_ms: float, echo_window_ms: float) -> bool:
    if latency_ms < 0 or latency_ms > echo_window_ms:
        return False
    return (
        msg.arbitration_id == request.arbitration_id
        and msg.dlc == request.dlc
        and bytes(msg.data) == bytes(request.data)
    )


# ---------------------------------------------------------------------------
# Baseline-model
# ---------------------------------------------------------------------------

class BaselineModel:
    def __init__(self):
        self.duration_s = 0.0
        self.total_frames = 0
        self.key_counts = Counter()             # (CAN-ID, DLC)
        self.payload_counts = defaultdict(Counter)
        self.family_counts = Counter()
        self.family_ids = defaultdict(set)
        self.family_dlc_counts = defaultdict(Counter)
        self.marker_counts = Counter()

    def learn(self, msg):
        key = (msg.arbitration_id, msg.dlc)
        payload = bytes(msg.data)
        family = family_of(msg.arbitration_id)

        self.total_frames += 1
        self.key_counts[key] += 1
        self.payload_counts[key][payload] += 1
        self.family_counts[family] += 1
        self.family_ids[family].add(msg.arbitration_id)
        self.family_dlc_counts[family][msg.dlc] += 1

        marker = marker_of(msg)
        if marker is not None:
            self.marker_counts[marker] += 1

    def add_duration(self, seconds: float):
        self.duration_s += max(0.0, seconds)

    def key_rate(self, key) -> float:
        return safe_rate(self.key_counts[key], self.duration_s)

    def family_rate(self, family: int) -> float:
        return safe_rate(self.family_counts[family], self.duration_s)

    def is_dynamic_family(self, family: int) -> bool:
        count = self.family_counts[family]
        if count < DYNAMIC_MIN_FRAMES:
            return False
        ratio = len(self.family_ids[family]) / count
        return ratio >= DYNAMIC_UNIQUE_RATIO

    def has_payload(self, key, payload: bytes) -> bool:
        return self.payload_counts[key][payload] > 0

    def summary_rows(self):
        for family in sorted(self.family_counts):
            count = self.family_counts[family]
            yield [
                utcnow(),
                f"{self.duration_s:.6f}",
                f"{family:04X}",
                count,
                f"{self.family_rate(family):.6f}",
                len(self.family_ids[family]),
                int(self.is_dynamic_family(family)),
                "|".join(
                    f"DLC{dlc}:{n}"
                    for dlc, n in sorted(self.family_dlc_counts[family].items())
                ),
            ]


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

class Logger:
    RAW_HEADER = [
        "utc", "host_mono", "bus_timestamp", "dir", "phase",
        "can_id_hex", "family_hex", "id_low16_hex", "dlc",
        "data_hex", "probe_family_hex", "probe_token_hex", "ad",
    ]

    RESULT_HEADER = [
        "utc", "probe_index", "probe_family_hex", "probe_token_hex",
        "ad", "tx_ok", "n_rx_frames", "n_response_groups",
        "n_response_frames", "response", "token_exact_present",
        "token_swapped_present", "id_relation", "first_latency_ms",
        "burst_ms", "response_signature", "response_ids",
        "candidate_reasons", "ad_relation_hint",
    ]

    RESPONSE_HEADER = [
        "utc", "probe_index", "probe_family_hex", "probe_token_hex",
        "ad", "response_can_id_hex", "response_family_hex",
        "response_id_low16_hex", "dlc", "n_frames",
        "baseline_count", "baseline_rate_hz", "expected_in_window",
        "threshold_count", "family_dynamic", "new_payload_count",
        "candidate", "candidate_reasons", "token_exact_present",
        "token_swapped_present", "id_exact", "id_swapped",
        "token_match_locations", "first_latency_ms", "last_latency_ms",
        "payload_count", "payload_samples",
    ]

    EVENT_HEADER = [
        "utc", "host_mono", "can_id_hex", "marker_hex",
        "marker_name", "data_hex", "probe_token_hex", "ad",
    ]

    BASELINE_HEADER = [
        "utc", "baseline_duration_s", "family_hex", "n_frames",
        "rate_hz", "distinct_can_ids", "dynamic_family", "dlc_counts",
    ]

    def __init__(self, prefix: str, log_beacon: bool = True):
        self.log_beacon = log_beacon
        self._n = 0
        self.raw_path = f"{prefix}_raw.csv"
        self.res_path = f"{prefix}_results.csv"
        self.rsp_path = f"{prefix}_responses.csv"
        self.evt_path = f"{prefix}_events.csv"
        self.bas_path = f"{prefix}_baseline.csv"

        self.raw = self._open(self.raw_path, self.RAW_HEADER)
        self.res = self._open(self.res_path, self.RESULT_HEADER)
        self.rsp = self._open(self.rsp_path, self.RESPONSE_HEADER)
        self.evt = self._open(self.evt_path, self.EVENT_HEADER)
        self.bas = self._open(self.bas_path, self.BASELINE_HEADER)

    @staticmethod
    def _open(path, header):
        exists = os.path.exists(path) and os.path.getsize(path) > 0
        fh = open(path, "a", newline="", encoding="utf-8")
        writer = csv.writer(fh)
        if not exists:
            writer.writerow(header)
            fh.flush()
        return fh, writer

    def frame(self, direction, msg, host_mono, phase, family, token, ad):
        if not self.log_beacon and direction == "RX" and is_beacon(msg.arbitration_id):
            return
        fh, writer = self.raw
        writer.writerow([
            utcnow(), f"{host_mono:.9f}", f"{getattr(msg, 'timestamp', 0.0):.9f}",
            direction, phase, f"{msg.arbitration_id:08X}",
            f"{family_of(msg.arbitration_id):04X}",
            f"{token_of(msg.arbitration_id):04X}", msg.dlc,
            hexdata(msg.data), "" if family is None else f"{family:04X}",
            "" if token is None else f"{token:04X}", ad,
        ])
        self._n += 1
        if self._n % FLUSH_EVERY == 0:
            fh.flush()

    def event(self, msg, host_mono, marker, probe_token, ad):
        fh, writer = self.evt
        writer.writerow([
            utcnow(), f"{host_mono:.9f}", f"{msg.arbitration_id:08X}",
            f"{marker:02X}", MARKER_NAMES.get(marker, "onbekend"),
            hexdata(msg.data),
            "" if probe_token is None else f"{probe_token:04X}", ad,
        ])
        fh.flush()

    def write_baseline(self, model: BaselineModel):
        fh, writer = self.bas
        for row in model.summary_rows():
            writer.writerow(row)
        fh.flush()

    def _ad_relation_hint(self, family, token, ad, signature):
        if not os.path.exists(self.res_path):
            return "?"
        prior = []
        try:
            with open(self.res_path, newline="", encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    if row.get("probe_family_hex", "").upper() != f"{family:04X}":
                        continue
                    if row.get("probe_token_hex", "").upper() != f"{token:04X}":
                        continue
                    old_ad = row.get("ad", "")
                    if old_ad and old_ad != ad:
                        prior.append(row.get("response_signature", ""))
        except (OSError, csv.Error):
            return "?"

        if not prior:
            return "?"
        if all(old == signature for old in prior):
            return "geen ID/DLC-verschil waargenomen"
        return "ID/DLC-verschil waargenomen; herhalen vereist"

    def result(self, probe_index, family, token, ad, tx_ok, analysis):
        signature = analysis.signature
        ad_hint = self._ad_relation_hint(family, token, ad, signature)
        candidates = analysis.candidates
        ids = sorted({f"{g.can_id:08X}" for g in candidates})
        reasons = sorted({reason for g in candidates for reason in g.reasons})
        n_candidate_frames = sum(len(g.frames) for g in candidates)

        fh, writer = self.res
        writer.writerow([
            utcnow(), probe_index, f"{family:04X}", f"{token:04X}", ad,
            int(tx_ok), len(analysis.all_frames), len(candidates),
            n_candidate_frames, int(analysis.response),
            int(analysis.exact_present), int(analysis.swapped_present),
            analysis.id_relation,
            "" if analysis.first_latency_ms is None else f"{analysis.first_latency_ms:.3f}",
            "" if analysis.burst_ms is None else f"{analysis.burst_ms:.3f}",
            signature, "|".join(ids), "|".join(reasons), ad_hint,
        ])
        fh.flush()

        rfh, rwriter = self.rsp
        for group in analysis.groups:
            relation = group.relation
            rwriter.writerow([
                utcnow(), probe_index, f"{family:04X}", f"{token:04X}", ad,
                f"{group.can_id:08X}", f"{family_of(group.can_id):04X}",
                f"{token_of(group.can_id):04X}", group.dlc, len(group.frames),
                group.baseline_count, f"{group.baseline_rate_hz:.6f}",
                f"{group.expected_count:.3f}", group.threshold_count,
                int(group.family_dynamic), group.new_payload_count,
                int(group.candidate), "|".join(group.reasons),
                int(relation.exact_present), int(relation.swapped_present),
                int(relation.id_exact), int(relation.id_swapped),
                "|".join(relation.locations),
                f"{group.first_latency_ms:.3f}",
                f"{group.last_latency_ms:.3f}",
                len(group.payloads), " || ".join(group.payloads[:8]),
            ])
        rfh.flush()

    def done_tokens(self, family):
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
        for fh, _ in (self.raw, self.res, self.rsp, self.evt, self.bas):
            try:
                fh.flush()
                fh.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Ontvangst, baseline en classificatie
# ---------------------------------------------------------------------------

def receive_for(bus, logger, seconds, phase, ad, baseline=None,
                probe_family=None, probe_token=None, t_tx=None,
                request=None, echo_window_ms=2.0,
                quiet_extend_s=0.0, max_extra_s=0.5):
    """
    Ontvangt frames. Als t_tx is gezet, worden CapturedFrame-records gemaakt.
    De quiet extension reageert op niet-beaconframes, maar is begrensd zodat
    normaal achtergrondverkeer het venster niet onbeperkt kan verlengen.
    """
    captured = []
    start = time.monotonic()
    base_deadline = start + seconds
    deadline = base_deadline
    hard_deadline = base_deadline + max(0.0, max_extra_s)

    while time.monotonic() < deadline and not _stop:
        msg = bus.recv(timeout=0.02)
        if msg is None:
            continue

        host_mono = time.monotonic()
        logger.frame("RX", msg, host_mono, phase,
                     probe_family, probe_token, ad)

        marker = marker_of(msg)
        if marker is not None and marker != MARKER_IDLE:
            logger.event(msg, host_mono, marker, probe_token, ad)
            print(f"      [marker {marker:02X}] "
                  f"{MARKER_NAMES.get(marker, 'onbekend')}")

        if baseline is not None:
            baseline.learn(msg)

        if t_tx is not None:
            latency_ms = (host_mono - t_tx) * 1000.0
            if request is not None and is_probable_own_echo(
                    msg, request, latency_ms, echo_window_ms):
                continue
            captured.append(CapturedFrame(msg, host_mono, latency_ms))

            if quiet_extend_s and not is_beacon(msg.arbitration_id):
                deadline = min(
                    hard_deadline,
                    max(deadline, host_mono + quiet_extend_s),
                )

    elapsed = time.monotonic() - start
    if baseline is not None:
        baseline.add_duration(elapsed)
    return captured, elapsed


def collect_baseline(bus, logger, seconds, ad) -> BaselineModel:
    model = BaselineModel()
    print(f"[*] Baseline-model opbouwen, {seconds:.1f} s ...")
    receive_for(
        bus, logger, seconds, phase="baseline", ad=ad, baseline=model,
    )
    logger.write_baseline(model)
    print(f"    {model.total_frames} frames in {model.duration_s:.2f} s; "
          f"{len(model.family_counts)} families; "
          f"{len(model.key_counts)} ID/DLC-combinaties")
    for family in sorted(model.family_counts):
        print(
            f"      family {family:04X}: {model.family_counts[family]:6d} frames, "
            f"{model.family_rate(family):8.2f} Hz, "
            f"{len(model.family_ids[family]):5d} IDs, "
            f"dynamic={'ja' if model.is_dynamic_family(family) else 'nee'}"
        )
    return model


def family_rate_increase(frames, baseline, duration_s, sigma, min_excess):
    observed = Counter(family_of(frame.msg.arbitration_id) for frame in frames)
    increased = set()
    for family, count in observed.items():
        expected = baseline.family_rate(family) * duration_s
        threshold = count_threshold(expected, sigma, min_excess)
        if count >= threshold:
            increased.add(family)
    return increased


def analyse_probe(frames, baseline, probe_token, duration_s,
                  sigma=4.0, min_excess=2) -> ProbeAnalysis:
    grouped = defaultdict(list)
    for frame in frames:
        grouped[(frame.msg.arbitration_id, frame.msg.dlc)].append(frame)

    increased_families = family_rate_increase(
        frames, baseline, duration_s, sigma, min_excess,
    )

    groups = []
    for key, items in sorted(grouped.items()):
        can_id, dlc = key
        family = family_of(can_id)
        baseline_count = baseline.key_counts[key]
        baseline_rate = baseline.key_rate(key)
        expected = baseline_rate * duration_s
        threshold = count_threshold(expected, sigma, min_excess)
        dynamic = baseline.is_dynamic_family(family)

        payloads = {bytes(item.msg.data) for item in items}
        new_payload_count = sum(
            1 for payload in payloads if not baseline.has_payload(key, payload)
        )

        # Eén relation-object voor de hele groep; locaties worden samengevoegd.
        relations = [find_token_relation(item.msg, probe_token) for item in items]
        locations = sorted({loc for rel in relations for loc in rel.locations})
        relation = TokenRelation(
            exact_present=any(rel.exact_present for rel in relations),
            swapped_present=any(rel.swapped_present for rel in relations),
            id_exact=any(rel.id_exact for rel in relations),
            id_swapped=any(rel.id_swapped for rel in relations),
            locations=locations,
        )

        marker_event = any(
            marker_of(item.msg) not in (None, MARKER_IDLE) for item in items
        )
        token_match = relation.exact_present or relation.swapped_present
        key_rate_up = len(items) >= threshold
        family_rate_up = family in increased_families

        reasons = []
        if baseline.family_counts[family] == 0:
            reasons.append("new_family")
        elif baseline_count == 0:
            reasons.append(
                "new_id_in_dynamic_family" if dynamic else "new_id"
            )
        if new_payload_count:
            reasons.append("new_payload")
        if key_rate_up:
            reasons.append("id_rate_above_baseline")
        if family_rate_up:
            reasons.append("family_rate_above_baseline")
        if marker_event:
            reasons.append("marker_event")
        if token_match:
            reasons.append("token_relation")

        # Dynamische families produceren vanzelf voortdurend nieuwe exacte IDs
        # en payloads. Dat is zonder extra correlatie geen responsebewijs.
        if family in BEACON_FAMILIES or dynamic:
            candidate = marker_event or token_match or family_rate_up
        else:
            candidate = (
                baseline.family_counts[family] == 0
                or baseline_count == 0
                or new_payload_count > 0
                or key_rate_up
                or family_rate_up
                or marker_event
                or token_match
            )

        groups.append(ResponseGroup(
            can_id=can_id,
            dlc=dlc,
            frames=items,
            baseline_count=baseline_count,
            baseline_rate_hz=baseline_rate,
            expected_count=expected,
            threshold_count=threshold,
            family_dynamic=dynamic,
            new_payload_count=new_payload_count,
            reasons=reasons,
            candidate=candidate,
            relation=relation,
        ))

    candidates = [group for group in groups if group.candidate]
    return ProbeAnalysis(groups, candidates, frames, duration_s)


# ---------------------------------------------------------------------------
# Probe-uitvoering en schermweergave
# ---------------------------------------------------------------------------

def drain(bus, logger, seconds, ad):
    receive_for(bus, logger, seconds, phase="settle", ad=ad)


def do_probe(bus, logger, baseline, probe_index, family, token, ad,
             window_s, quiet_s, settle_s, max_extra_s,
             echo_window_ms, sigma, min_excess):
    drain(bus, logger, settle_s, ad)

    request = build_request(family, token)
    tx_ok = True
    t_tx = time.monotonic()
    try:
        bus.send(request)
        logger.frame("TX", request, t_tx, "probe_tx", family, token, ad)
    except can.CanError as exc:
        tx_ok = False
        print(f"      [!] TX mislukt: {exc}")

    frames, elapsed = receive_for(
        bus, logger, window_s, phase="probe_rx", ad=ad,
        probe_family=family, probe_token=token, t_tx=t_tx,
        request=request, echo_window_ms=echo_window_ms,
        quiet_extend_s=quiet_s, max_extra_s=max_extra_s,
    )
    analysis = analyse_probe(
        frames, baseline, token, elapsed, sigma=sigma,
        min_excess=min_excess,
    )
    logger.result(probe_index, family, token, ad, tx_ok, analysis)
    return tx_ok, analysis


def describe_analysis(analysis, indent="    "):
    if not analysis.candidates:
        print(f"{indent}geen kandidaat-response boven baseline")
        return

    print(
        f"{indent}{len(analysis.candidates)} kandidaatgroep(en), "
        f"{sum(len(g.frames) for g in analysis.candidates)} frames, "
        f"eerste na {analysis.first_latency_ms:.3f} ms, "
        f"burst {analysis.burst_ms:.3f} ms"
    )
    for group in analysis.candidates:
        relation = group.relation
        print(
            f"{indent}  ID {group.can_id:08X} DLC{group.dlc} "
            f"n={len(group.frames)} baseline={group.baseline_rate_hz:.3f} Hz "
            f"lat={group.first_latency_ms:.3f}..{group.last_latency_ms:.3f} ms"
        )
        print(f"{indent}     reden: {', '.join(group.reasons)}")
        print(
            f"{indent}     token exact={'ja' if relation.exact_present else 'nee'}, "
            f"swapped={'ja' if relation.swapped_present else 'nee'}, "
            f"locaties={','.join(relation.locations) if relation.locations else '-'}"
        )
        for payload in group.payloads[:6]:
            print(f"{indent}     {payload}")
        if len(group.payloads) > 6:
            print(f"{indent}     ... en {len(group.payloads) - 6} andere")


# ---------------------------------------------------------------------------
# Modi
# ---------------------------------------------------------------------------

def mode_baseline(bus, logger, seconds, ad):
    model = collect_baseline(bus, logger, seconds, ad)
    n_beacon = sum(
        count for (can_id, _dlc), count in model.key_counts.items()
        if is_beacon(can_id)
    )
    n_other = model.total_frames - n_beacon
    print(f"[*] Beaconframes: {n_beacon} ({safe_rate(n_beacon, model.duration_s):.1f}/s)")
    print(f"[*] Overige frames: {n_other} ({safe_rate(n_other, model.duration_s):.1f}/s)")
    if model.total_frames == 0:
        print("\n    GEEN VERKEER. Controleer bitrate, kanaal, bekabeling en voeding.")
    elif n_beacon and abs(safe_rate(n_beacon, model.duration_s) - 400) > 120:
        print("\n    Let op: verwacht was ongeveer 400 beaconframes/s.")


def mode_verify(bus, logger, baseline, family, token, ad, repeats,
                interval_s, common):
    print(
        f"[*] VERIFY family {family:04X}, token {token:04X}, AD={ad}, "
        f"{repeats} herhalingen"
    )
    hits = 0
    latencies = []
    for index in range(1, repeats + 1):
        if _stop:
            break
        _tx_ok, analysis = do_probe(
            bus, logger, baseline, index, family, token, ad, **common,
        )
        if analysis.response:
            hits += 1
            latencies.append(analysis.first_latency_ms)
            print(
                f"  {index:3d}/{repeats} RESPONSE "
                f"groups={len(analysis.candidates):2d} "
                f"frames={sum(len(g.frames) for g in analysis.candidates):3d} "
                f"lat={analysis.first_latency_ms:7.3f} ms "
                f"exact={'ja' if analysis.exact_present else 'nee'} "
                f"swapped={'ja' if analysis.swapped_present else 'nee'}"
            )
        else:
            print(f"  {index:3d}/{repeats} -- geen kandidaat-response")

        rest = interval_s - common["window_s"] - common["settle_s"]
        if rest > 0 and not _stop:
            time.sleep(rest)

    print(f"\n[*] Kandidaat-response bij {hits}/{repeats} probes.")
    if latencies:
        print(
            f"    latency min={min(latencies):.3f}, "
            f"gem={sum(latencies)/len(latencies):.3f}, "
            f"max={max(latencies):.3f} ms"
        )


def mode_single(bus, logger, baseline, family, token, ad, common):
    print(f"[*] SINGLE family {family:04X}, token {token:04X}, AD={ad}")
    _tx_ok, analysis = do_probe(
        bus, logger, baseline, 1, family, token, ad, **common,
    )
    describe_analysis(analysis)


def mode_tokens(bus, logger, baseline, family, tokens, ad, common):
    print(
        f"[*] TOKENS family {family:04X}, AD={ad}: "
        + ", ".join(f"{token:04X}" for token in tokens)
    )
    results = []
    for index, token in enumerate(tokens, 1):
        if _stop:
            break
        print(f"\n  probe token {token:04X}")
        _tx_ok, analysis = do_probe(
            bus, logger, baseline, index, family, token, ad, **common,
        )
        describe_analysis(analysis, indent="    ")
        results.append((token, analysis))

    print("\n[*] Samenvatting")
    print("    Probe  Respons  Exact  Swapped  ID-relatie")
    for token, analysis in results:
        print(
            f"    {token:04X}   "
            f"{'ja ':7s if analysis.response else 'nee':7s}  "
            f"{'ja ' if analysis.exact_present else 'nee':5s}  "
            f"{'ja ' if analysis.swapped_present else 'nee':7s}  "
            f"{analysis.id_relation}"
        )

    responses = [analysis for _, analysis in results if analysis.response]
    if len(responses) > 1 and all(
            not a.exact_present and not a.swapped_present for a in responses):
        print(
            "\n    Voorlopige aanwijzing: de probe-token wordt niet rechtstreeks "
            "geëchood.\n    Dit bewijst niet dat de token betekenisloos of willekeurig is; "
            "alleen dat\n    hij geen direct teruggestuurde unitidentiteit lijkt te zijn."
        )


def mode_sweep(bus, logger, baseline, family, start, end, order, ad,
               stop_on_hit, resume, common):
    tokens = list(range(start, end + 1))
    if resume:
        done = logger.done_tokens(family)
        before = len(tokens)
        tokens = [token for token in tokens if token not in done]
        print(f"[*] Hervatten: {before - len(tokens)} gedaan, {len(tokens)} resterend.")
    if order == "random":
        random.shuffle(tokens)

    estimate = common["window_s"] + common["settle_s"]
    print(
        f"[*] SWEEP family {family:04X}, AD={ad}: {len(tokens)} tokens; "
        f"minimaal ~{len(tokens) * estimate / 3600:.2f} uur"
    )
    print("[*] Ctrl-C stopt netjes; --resume hervat later.")

    hits = 0
    started = time.monotonic()
    for index, token in enumerate(tokens, 1):
        if _stop:
            break
        _tx_ok, analysis = do_probe(
            bus, logger, baseline, index, family, token, ad, **common,
        )
        if analysis.response:
            hits += 1
            print(
                f"  >>> RESPONSE {token:04X}: "
                f"groups={len(analysis.candidates)}, "
                f"lat={analysis.first_latency_ms:.3f} ms, "
                f"exact={'ja' if analysis.exact_present else 'nee'}, "
                f"swapped={'ja' if analysis.swapped_present else 'nee'}"
            )
            if stop_on_hit:
                break

        if index % 50 == 0 or index == len(tokens):
            elapsed = time.monotonic() - started
            rate = index / elapsed if elapsed else 0.0
            eta_min = (len(tokens) - index) / rate / 60.0 if rate else 0.0
            print(
                f"  [{index}/{len(tokens)}] responses={hits}, "
                f"{rate * 60:.1f} tokens/min, ETA={eta_min:.1f} min"
            )

    print(f"\n[*] Sweep afgerond of onderbroken. Kandidaat-responses: {hits}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def open_bus(channel, bitrate):
    try:
        return can.Bus(
            interface="pcan", channel=channel, bitrate=bitrate,
            receive_own_messages=False,
        )
    except TypeError:
        return can.interface.Bus(
            bustype="pcan", channel=channel, bitrate=bitrate,
        )


def main():
    parser = argparse.ArgumentParser(
        description="DAB Active Driver Plus CAN request/response probe v3",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--mode", required=True,
        choices=["baseline", "verify", "single", "tokens", "sweep"],
    )
    parser.add_argument("--channel", default="PCAN_USBBUS1")
    parser.add_argument("--bitrate", type=int, default=1000000)
    parser.add_argument("--out", default="dab_probe")
    parser.add_argument("--ad", default="?",
                        help="ingestelde AD-waarde, bijvoorbeeld AUTO, 0, 1, 2 of 3")
    parser.add_argument("--no-raw-beacon", action="store_true")

    parser.add_argument("--family", type=parse_int, default=DEFAULT_REQ_FAMILY)
    parser.add_argument("--token", type=parse_int, default=KNOWN_GOOD_TOKEN)
    parser.add_argument(
        "--tokens", default="0x0001,0x8000,0xFFFF,0xC82D",
        help="kommagescheiden lijst voor mode=tokens",
    )

    parser.add_argument("--window", type=float, default=0.25)
    parser.add_argument("--quiet", type=float, default=0.05)
    parser.add_argument("--max-extra", type=float, default=0.50,
                        help="maximale verlenging van het responsevenster")
    parser.add_argument("--settle", type=float, default=0.05)
    parser.add_argument("--echo-window-ms", type=float, default=2.0)

    parser.add_argument("--baseline-seconds", type=float, default=10.0,
                        help="baseline vóór actieve probes")
    parser.add_argument("--sigma", type=float, default=4.0,
                        help="drempel voor rate boven baseline")
    parser.add_argument("--min-excess", type=int, default=2,
                        help="minimum aantal frames voor rate-detectie")

    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--interval", type=float, default=5.0)

    parser.add_argument("--start", type=parse_int, default=0x0000)
    parser.add_argument("--end", type=parse_int, default=0xFFFF)
    parser.add_argument(
        "--order", choices=["sequential", "random"], default="sequential",
    )
    parser.add_argument("--stop-on-hit", action="store_true")
    parser.add_argument("--resume", action="store_true")

    args = parser.parse_args()

    for name, value in (
        ("family", args.family), ("token", args.token),
        ("start", args.start), ("end", args.end),
    ):
        if not 0 <= value <= (0x1FFF if name == "family" else 0xFFFF):
            parser.error(f"--{name} buiten geldig bereik")
    if args.start > args.end:
        parser.error("--start moet kleiner dan of gelijk aan --end zijn")
    if args.baseline_seconds <= 0:
        parser.error("--baseline-seconds moet groter dan nul zijn")

    print("=" * 78)
    print(f" DAB probe v{VERSION} | {utcnow()}")
    print(
        f" kanaal={args.channel} bitrate={args.bitrate} "
        f"family=0x{args.family:04X} AD={args.ad}"
    )
    print(f" raw beacon logging={'nee' if args.no_raw_beacon else 'ja'}")
    print("=" * 78)

    logger = Logger(args.out, log_beacon=not args.no_raw_beacon)
    bus = None
    try:
        try:
            bus = open_bus(args.channel, args.bitrate)
        except Exception as exc:
            print(f"\n[!] Kan CAN-bus niet openen: {exc}")
            print("    Sluit PCAN-View en controleer kanaal, bitrate en driver.")
            return 2

        if args.mode == "baseline":
            mode_baseline(bus, logger, args.baseline_seconds, args.ad)
            return 0

        baseline = collect_baseline(
            bus, logger, args.baseline_seconds, args.ad,
        )
        if baseline.total_frames == 0:
            print("[!] Geen baselineverkeer ontvangen; actieve probe wordt afgebroken.")
            return 3

        common = dict(
            window_s=args.window,
            quiet_s=args.quiet,
            settle_s=args.settle,
            max_extra_s=args.max_extra,
            echo_window_ms=args.echo_window_ms,
            sigma=args.sigma,
            min_excess=args.min_excess,
        )

        if args.mode == "verify":
            mode_verify(
                bus, logger, baseline, args.family, args.token, args.ad,
                args.repeats, args.interval, common,
            )
        elif args.mode == "single":
            mode_single(
                bus, logger, baseline, args.family, args.token, args.ad, common,
            )
        elif args.mode == "tokens":
            tokens = [
                parse_int(item) for item in args.tokens.split(",") if item.strip()
            ]
            invalid = [token for token in tokens if not 0 <= token <= 0xFFFF]
            if invalid:
                parser.error("één of meer tokens vallen buiten 0x0000..0xFFFF")
            mode_tokens(
                bus, logger, baseline, args.family, tokens, args.ad, common,
            )
        elif args.mode == "sweep":
            mode_sweep(
                bus, logger, baseline, args.family, args.start, args.end,
                args.order, args.ad, args.stop_on_hit, args.resume, common,
            )
        return 0

    finally:
        if bus is not None:
            try:
                bus.shutdown()
            except Exception:
                pass
        logger.close()
        print(
            f"\n[*] Logs: {args.out}_raw.csv, {args.out}_results.csv, "
            f"{args.out}_responses.csv, {args.out}_events.csv, "
            f"{args.out}_baseline.csv"
        )


if __name__ == "__main__":
    sys.exit(main())
