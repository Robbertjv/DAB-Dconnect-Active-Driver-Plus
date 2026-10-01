#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dab_probe_v3_1.py -- DAB Active Driver Plus CAN request/response probe

Belangrijkste eigenschappen
---------------------------
* Bouwt vóór actieve probes een baseline-model op.
* Selecteert kandidaat-responses vóórdat naar de probe-token wordt gezocht.
* Zoekt de token exact, byte-swapped en in de onderste 16 bits van de CAN-ID.
* Voorkomt dat het vaste beaconvoorvoegsel 01 00 bij token 0001 een response
  veroorzaakt.
* Een marker die al in de baseline voorkwam is niet automatisch een response.
* Gebruikt waar mogelijk de PCAN-timestamp voor nauwkeurige responslatency.
* Registreert AD, response-signature, redenen en payloadvoorbeelden in CSV.

Afhankelijkheden
----------------
pip install python-can uptime

VEILIGHEID
----------
Dit script zendt naar een live pompinverter. Gebruik actieve modi alleen in een
veilige testopstelling.
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
    sys.exit("python-can ontbreekt. Installeer met: python -m pip install python-can")


VERSION = "3.1"
BEACON_FAMILIES = {0x0001, 0x0011}
KNOWN_GOOD_TOKEN = 0xC82D
DEFAULT_REQ_FAMILY = 0x0012
MARKER_IDLE = 0x03
FLUSH_EVERY = 200
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
    return " ".join(f"{byte:02X}" for byte in data)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def parse_int(text: str) -> int:
    text = text.strip()
    if text.lower().endswith("h"):
        return int(text[:-1], 16)
    return int(text, 0)


def marker_of(msg):
    if (
        family_of(msg.arbitration_id) == 0x0001
        and msg.dlc == 7
        and len(msg.data) >= 5
    ):
        return msg.data[4]
    return None


def safe_rate(count: int, seconds: float) -> float:
    return count / seconds if seconds > 0 else 0.0


def count_threshold(expected: float, sigma: float, min_excess: int) -> int:
    return max(
        min_excess,
        int(math.ceil(expected + sigma * math.sqrt(expected + 1.0))),
    )


def response_latency_ms(msg, host_mono, tx_mono, tx_epoch):
    """
    Gebruik de PCAN-timestamp wanneer python-can deze naar Epoch heeft omgezet.
    Val anders terug op de monotone hostklok.
    """
    bus_timestamp = float(getattr(msg, "timestamp", 0.0) or 0.0)

    if bus_timestamp > 1_000_000_000 and tx_epoch is not None:
        latency = (bus_timestamp - tx_epoch) * 1000.0
        if -100.0 <= latency <= 10_000.0:
            return latency

    return (host_mono - tx_mono) * 1000.0


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
        return min(frame.latency_ms for frame in self.frames)

    @property
    def last_latency_ms(self):
        return max(frame.latency_ms for frame in self.frames)

    @property
    def payloads(self):
        return sorted({hexdata(frame.msg.data) for frame in self.frames})


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
        return min(group.first_latency_ms for group in self.candidates)

    @property
    def last_latency_ms(self):
        if not self.candidates:
            return None
        return max(group.last_latency_ms for group in self.candidates)

    @property
    def burst_ms(self):
        if not self.candidates:
            return None
        return self.last_latency_ms - self.first_latency_ms

    @property
    def exact_present(self):
        return any(group.relation.exact_present for group in self.candidates)

    @property
    def swapped_present(self):
        return any(group.relation.swapped_present for group in self.candidates)

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
            f"{group.can_id:08X}/DLC{group.dlc}"
            for group in sorted(
                self.candidates,
                key=lambda item: (item.can_id, item.dlc),
            )
        )


# ---------------------------------------------------------------------------
# Tokenanalyse
# ---------------------------------------------------------------------------

def find_token_relation(msg, probe_token: int) -> TokenRelation:
    """
    Voor token C82D:
      exact   = C8 2D
      swapped = 2D C8

    Er wordt op iedere mogelijke twee-byte-offset in de kandidaat-response
    gezocht. Deze functie bepaalt niet zelf of een frame een response is.
    """
    token = probe_token & 0xFFFF
    exact_bytes = bytes([(token >> 8) & 0xFF, token & 0xFF])
    swapped_bytes = bytes([token & 0xFF, (token >> 8) & 0xFF])
    payload = bytes(msg.data)

    exact_payload = False
    swapped_payload = False
    locations = []

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


def is_probable_own_echo(msg, request, latency_ms, echo_window_ms) -> bool:
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
        self.key_counts = Counter()
        self.payload_counts = defaultdict(Counter)
        self.byte_values = defaultdict(lambda: [set() for _ in range(8)])
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
        for offset, value in enumerate(payload[:8]):
            self.byte_values[key][offset].add(value)

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
        return len(self.family_ids[family]) / count >= DYNAMIC_UNIQUE_RATIO

    def payload_pattern_changed(self, key, payload: bytes) -> bool:
        """
        Alleen een wijziging op een tijdens de baseline constant gebleven
        bytepositie geldt als een nieuw payloadpatroon.
        """
        if self.key_counts[key] == 0:
            return True

        for offset, value in enumerate(payload[:8]):
            observed = self.byte_values[key][offset]
            if observed and len(observed) == 1 and value not in observed:
                return True
        return False

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
                    f"DLC{dlc}:{number}"
                    for dlc, number in sorted(
                        self.family_dlc_counts[family].items()
                    )
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
        file_handle = open(path, "a", newline="", encoding="utf-8")
        writer = csv.writer(file_handle)
        if not exists:
            writer.writerow(header)
            file_handle.flush()
        return file_handle, writer

    def frame(self, direction, msg, host_mono, phase, family, token, ad):
        if (
            not self.log_beacon
            and direction == "RX"
            and is_beacon(msg.arbitration_id)
        ):
            return

        file_handle, writer = self.raw
        writer.writerow([
            utcnow(),
            f"{host_mono:.9f}",
            f"{getattr(msg, 'timestamp', 0.0):.9f}",
            direction,
            phase,
            f"{msg.arbitration_id:08X}",
            f"{family_of(msg.arbitration_id):04X}",
            f"{token_of(msg.arbitration_id):04X}",
            msg.dlc,
            hexdata(msg.data),
            "" if family is None else f"{family:04X}",
            "" if token is None else f"{token:04X}",
            ad,
        ])
        self._n += 1
        if self._n % FLUSH_EVERY == 0:
            file_handle.flush()

    def event(self, msg, host_mono, marker, probe_token, ad):
        file_handle, writer = self.evt
        writer.writerow([
            utcnow(),
            f"{host_mono:.9f}",
            f"{msg.arbitration_id:08X}",
            f"{marker:02X}",
            MARKER_NAMES.get(marker, "onbekend"),
            hexdata(msg.data),
            "" if probe_token is None else f"{probe_token:04X}",
            ad,
        ])
        file_handle.flush()

    def write_baseline(self, model: BaselineModel):
        file_handle, writer = self.bas
        for row in model.summary_rows():
            writer.writerow(row)
        file_handle.flush()

    def _ad_relation_hint(self, family, token, ad, signature):
        if not os.path.exists(self.res_path):
            return "?"

        prior_signatures = []
        try:
            with open(self.res_path, newline="", encoding="utf-8") as source:
                for row in csv.DictReader(source):
                    if row.get("probe_family_hex", "").upper() != f"{family:04X}":
                        continue
                    if row.get("probe_token_hex", "").upper() != f"{token:04X}":
                        continue
                    old_ad = row.get("ad", "")
                    if old_ad and old_ad != ad:
                        prior_signatures.append(
                            row.get("response_signature", "")
                        )
        except (OSError, csv.Error):
            return "?"

        if not prior_signatures:
            return "?"
        if all(old == signature for old in prior_signatures):
            return "geen ID/DLC-verschil waargenomen"
        return "ID/DLC-verschil waargenomen; herhalen vereist"

    def result(self, probe_index, family, token, ad, tx_ok, analysis):
        signature = analysis.signature
        ad_hint = self._ad_relation_hint(family, token, ad, signature)
        candidates = analysis.candidates
        response_ids = sorted({f"{group.can_id:08X}" for group in candidates})
        reasons = sorted({
            reason
            for group in candidates
            for reason in group.reasons
        })
        candidate_frames = sum(len(group.frames) for group in candidates)

        file_handle, writer = self.res
        writer.writerow([
            utcnow(),
            probe_index,
            f"{family:04X}",
            f"{token:04X}",
            ad,
            int(tx_ok),
            len(analysis.all_frames),
            len(candidates),
            candidate_frames,
            int(analysis.response),
            int(analysis.exact_present),
            int(analysis.swapped_present),
            analysis.id_relation,
            "" if analysis.first_latency_ms is None
            else f"{analysis.first_latency_ms:.3f}",
            "" if analysis.burst_ms is None
            else f"{analysis.burst_ms:.3f}",
            signature,
            "|".join(response_ids),
            "|".join(reasons),
            ad_hint,
        ])
        file_handle.flush()

        # Alleen echte kandidaat-responses in responses.csv.
        response_handle, response_writer = self.rsp
        for group in analysis.candidates:
            relation = group.relation
            response_writer.writerow([
                utcnow(),
                probe_index,
                f"{family:04X}",
                f"{token:04X}",
                ad,
                f"{group.can_id:08X}",
                f"{family_of(group.can_id):04X}",
                f"{token_of(group.can_id):04X}",
                group.dlc,
                len(group.frames),
                group.baseline_count,
                f"{group.baseline_rate_hz:.6f}",
                f"{group.expected_count:.3f}",
                group.threshold_count,
                int(group.family_dynamic),
                group.new_payload_count,
                int(group.candidate),
                "|".join(group.reasons),
                int(relation.exact_present),
                int(relation.swapped_present),
                int(relation.id_exact),
                int(relation.id_swapped),
                "|".join(relation.locations),
                f"{group.first_latency_ms:.3f}",
                f"{group.last_latency_ms:.3f}",
                len(group.payloads),
                " || ".join(group.payloads[:8]),
            ])
        response_handle.flush()

    def done_tokens(self, family, ad=None):
        done = set()
        if not os.path.exists(self.res_path):
            return done

        with open(self.res_path, newline="", encoding="utf-8") as source:
            for row in csv.DictReader(source):
                if row.get("probe_family_hex", "").upper() != f"{family:04X}":
                    continue
                if ad is not None and row.get("ad", "") != str(ad):
                    continue
                try:
                    done.add(int(row["probe_token_hex"], 16))
                except (KeyError, TypeError, ValueError):
                    pass
        return done

    def close(self):
        for file_handle, _writer in (
            self.raw,
            self.res,
            self.rsp,
            self.evt,
            self.bas,
        ):
            try:
                file_handle.flush()
                file_handle.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Ontvangst, baseline en classificatie
# ---------------------------------------------------------------------------

def receive_for(
    bus,
    logger,
    seconds,
    phase,
    ad,
    baseline=None,
    probe_family=None,
    probe_token=None,
    t_tx=None,
    t_tx_epoch=None,
    request=None,
    echo_window_ms=2.0,
    quiet_extend_s=0.0,
    max_extra_s=0.5,
):
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
        logger.frame(
            "RX",
            msg,
            host_mono,
            phase,
            probe_family,
            probe_token,
            ad,
        )

        marker = marker_of(msg)
        if marker is not None and marker != MARKER_IDLE:
            logger.event(msg, host_mono, marker, probe_token, ad)
            print(
                f"      [marker {marker:02X}] "
                f"{MARKER_NAMES.get(marker, 'onbekend')}"
            )

        if baseline is not None:
            baseline.learn(msg)

        if t_tx is not None:
            latency_ms = response_latency_ms(
                msg,
                host_mono,
                t_tx,
                t_tx_epoch,
            )

            # Een hardwaretimestamp vóór de TX hoort bij een oud queueframe.
            if latency_ms < -0.5:
                continue

            if (
                request is not None
                and is_probable_own_echo(
                    msg,
                    request,
                    latency_ms,
                    echo_window_ms,
                )
            ):
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
        bus,
        logger,
        seconds,
        phase="baseline",
        ad=ad,
        baseline=model,
    )
    logger.write_baseline(model)

    print(
        f"    {model.total_frames} frames in {model.duration_s:.2f} s; "
        f"{len(model.family_counts)} families; "
        f"{len(model.key_counts)} ID/DLC-combinaties"
    )
    for family in sorted(model.family_counts):
        print(
            f"      family {family:04X}: "
            f"{model.family_counts[family]:6d} frames, "
            f"{model.family_rate(family):8.2f} Hz, "
            f"{len(model.family_ids[family]):5d} IDs, "
            f"dynamic={'ja' if model.is_dynamic_family(family) else 'nee'}"
        )
    return model


def family_rate_increase(frames, baseline, duration_s, sigma, min_excess):
    observed = Counter(
        family_of(frame.msg.arbitration_id)
        for frame in frames
    )
    increased = set()

    for family, count in observed.items():
        expected = baseline.family_rate(family) * duration_s
        threshold = count_threshold(expected, sigma, min_excess)
        if count >= threshold:
            increased.add(family)
    return increased


def analyse_probe(
    frames,
    baseline,
    probe_token,
    duration_s,
    sigma=4.0,
    min_excess=2,
) -> ProbeAnalysis:
    grouped = defaultdict(list)
    for frame in frames:
        grouped[(frame.msg.arbitration_id, frame.msg.dlc)].append(frame)

    increased_families = family_rate_increase(
        frames,
        baseline,
        duration_s,
        sigma,
        min_excess,
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
            1
            for payload in payloads
            if baseline.payload_pattern_changed(key, payload)
        )

        relations = [
            find_token_relation(item.msg, probe_token)
            for item in items
        ]
        locations = sorted({
            location
            for relation in relations
            for location in relation.locations
        })
        relation = TokenRelation(
            exact_present=any(item.exact_present for item in relations),
            swapped_present=any(item.swapped_present for item in relations),
            id_exact=any(item.id_exact for item in relations),
            id_swapped=any(item.id_swapped for item in relations),
            locations=locations,
        )

        marker_values = {
            marker_of(item.msg)
            for item in items
            if marker_of(item.msg) not in (None, MARKER_IDLE)
        }
        novel_marker = any(
            baseline.marker_counts[marker] == 0
            for marker in marker_values
        )

        token_match = relation.exact_present or relation.swapped_present
        key_rate_up = len(items) >= threshold
        family_rate_up = family in increased_families

        reasons = []
        if baseline.family_counts[family] == 0:
            reasons.append("new_family")
        elif baseline_count == 0:
            reasons.append(
                "new_id_in_dynamic_family"
                if dynamic
                else "new_id"
            )
        if new_payload_count:
            reasons.append("new_payload_pattern")
        if key_rate_up:
            reasons.append("id_rate_above_baseline")
        if family_rate_up:
            reasons.append("family_rate_above_baseline")
        if novel_marker:
            reasons.append("new_marker_value")
        if token_match:
            reasons.append("token_relation")

        # Cruciaal: token_match bepaalt niet of iets een response is.
        # Eerst onafhankelijke responseclassificatie, daarna tokenanalyse.
        if family in BEACON_FAMILIES or dynamic:
            candidate = novel_marker or family_rate_up
        else:
            candidate = (
                baseline.family_counts[family] == 0
                or baseline_count == 0
                or new_payload_count > 0
                or key_rate_up
                or family_rate_up
                or novel_marker
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
    return ProbeAnalysis(
        groups=groups,
        candidates=candidates,
        all_frames=frames,
        capture_duration_s=duration_s,
    )


# ---------------------------------------------------------------------------
# Probe-uitvoering en schermweergave
# ---------------------------------------------------------------------------

def drain(bus, logger, seconds, ad):
    receive_for(
        bus,
        logger,
        seconds,
        phase="settle",
        ad=ad,
    )


def do_probe(
    bus,
    logger,
    baseline,
    probe_index,
    family,
    token,
    ad,
    window_s,
    quiet_s,
    settle_s,
    max_extra_s,
    echo_window_ms,
    sigma,
    min_excess,
):
    drain(bus, logger, settle_s, ad)

    request = build_request(family, token)
    tx_ok = True
    t_tx = time.monotonic()
    t_tx_epoch = time.time()

    try:
        bus.send(request)
        logger.frame(
            "TX",
            request,
            t_tx,
            "probe_tx",
            family,
            token,
            ad,
        )
    except can.CanError as exc:
        tx_ok = False
        print(f"      [!] TX mislukt: {exc}")

    frames, elapsed = receive_for(
        bus,
        logger,
        window_s,
        phase="probe_rx",
        ad=ad,
        probe_family=family,
        probe_token=token,
        t_tx=t_tx,
        t_tx_epoch=t_tx_epoch,
        request=request,
        echo_window_ms=echo_window_ms,
        quiet_extend_s=quiet_s,
        max_extra_s=max_extra_s,
    )

    analysis = analyse_probe(
        frames,
        baseline,
        token,
        elapsed,
        sigma=sigma,
        min_excess=min_excess,
    )
    logger.result(
        probe_index,
        family,
        token,
        ad,
        tx_ok,
        analysis,
    )
    return tx_ok, analysis


def describe_analysis(analysis, indent="    "):
    if not analysis.candidates:
        print(f"{indent}geen kandidaat-response boven baseline")
        return

    candidate_frames = sum(
        len(group.frames)
        for group in analysis.candidates
    )
    print(
        f"{indent}{len(analysis.candidates)} kandidaatgroep(en), "
        f"{candidate_frames} frames, "
        f"eerste na {analysis.first_latency_ms:.3f} ms, "
        f"burst {analysis.burst_ms:.3f} ms"
    )

    for group in analysis.candidates:
        relation = group.relation
        print(
            f"{indent}  ID {group.can_id:08X} DLC{group.dlc} "
            f"n={len(group.frames)} "
            f"baseline={group.baseline_rate_hz:.3f} Hz "
            f"lat={group.first_latency_ms:.3f}.."
            f"{group.last_latency_ms:.3f} ms"
        )
        print(f"{indent}     reden: {', '.join(group.reasons)}")
        print(
            f"{indent}     token "
            f"exact={'ja' if relation.exact_present else 'nee'}, "
            f"swapped={'ja' if relation.swapped_present else 'nee'}, "
            f"locaties="
            f"{','.join(relation.locations) if relation.locations else '-'}"
        )
        for payload in group.payloads[:6]:
            print(f"{indent}     {payload}")
        if len(group.payloads) > 6:
            print(
                f"{indent}     ... en "
                f"{len(group.payloads) - 6} andere"
            )


# ---------------------------------------------------------------------------
# Modi
# ---------------------------------------------------------------------------

def mode_baseline(bus, logger, seconds, ad):
    model = collect_baseline(bus, logger, seconds, ad)
    beacon_count = sum(
        count
        for (can_id, _dlc), count in model.key_counts.items()
        if is_beacon(can_id)
    )
    other_count = model.total_frames - beacon_count

    print(
        f"[*] Beaconframes: {beacon_count} "
        f"({safe_rate(beacon_count, model.duration_s):.1f}/s)"
    )
    print(
        f"[*] Overige frames: {other_count} "
        f"({safe_rate(other_count, model.duration_s):.1f}/s)"
    )

    if model.total_frames == 0:
        print(
            "\n    GEEN VERKEER. Controleer bitrate, kanaal, "
            "bekabeling en voeding."
        )
    elif (
        beacon_count
        and abs(safe_rate(beacon_count, model.duration_s) - 400) > 120
    ):
        print("\n    Let op: verwacht was ongeveer 400 beaconframes/s.")


def mode_verify(
    bus,
    logger,
    baseline,
    family,
    token,
    ad,
    repeats,
    interval_s,
    common,
):
    print(
        f"[*] VERIFY family {family:04X}, token {token:04X}, "
        f"AD={ad}, {repeats} herhalingen"
    )
    hits = 0
    latencies = []

    for index in range(1, repeats + 1):
        if _stop:
            break

        _tx_ok, analysis = do_probe(
            bus,
            logger,
            baseline,
            index,
            family,
            token,
            ad,
            **common,
        )

        if analysis.response:
            hits += 1
            latencies.append(analysis.first_latency_ms)
            print(
                f"  {index:3d}/{repeats} RESPONSE "
                f"groups={len(analysis.candidates):2d} "
                f"frames="
                f"{sum(len(g.frames) for g in analysis.candidates):3d} "
                f"lat={analysis.first_latency_ms:7.3f} ms "
                f"exact={'ja' if analysis.exact_present else 'nee'} "
                f"swapped={'ja' if analysis.swapped_present else 'nee'}"
            )
        else:
            print(
                f"  {index:3d}/{repeats} -- "
                f"geen kandidaat-response"
            )

        rest = (
            interval_s
            - common["window_s"]
            - common["settle_s"]
        )
        if rest > 0 and not _stop:
            time.sleep(rest)

    print(f"\n[*] Kandidaat-response bij {hits}/{repeats} probes.")
    if latencies:
        print(
            f"    latency min={min(latencies):.3f}, "
            f"gem={sum(latencies) / len(latencies):.3f}, "
            f"max={max(latencies):.3f} ms"
        )


def mode_single(bus, logger, baseline, family, token, ad, common):
    print(
        f"[*] SINGLE family {family:04X}, "
        f"token {token:04X}, AD={ad}"
    )
    _tx_ok, analysis = do_probe(
        bus,
        logger,
        baseline,
        1,
        family,
        token,
        ad,
        **common,
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
            bus,
            logger,
            baseline,
            index,
            family,
            token,
            ad,
            **common,
        )
        describe_analysis(analysis)
        results.append((token, analysis))

    print("\n[*] Samenvatting")
    print(
        "    Probe  Respons  Exact  Swapped  "
        "ID-relatie      Response-signature"
    )

    for token, analysis in results:
        response_text = "ja" if analysis.response else "nee"
        exact_text = "ja" if analysis.exact_present else "nee"
        swapped_text = "ja" if analysis.swapped_present else "nee"
        print(
            f"    {token:04X}   "
            f"{response_text:7s}  "
            f"{exact_text:5s}  "
            f"{swapped_text:7s}  "
            f"{analysis.id_relation:15s} "
            f"{analysis.signature}"
        )

    responses = [
        analysis
        for _token, analysis in results
        if analysis.response
    ]

    if len(responses) > 1:
        signatures = {
            analysis.signature
            for analysis in responses
        }
        if len(signatures) == 1:
            print(
                "\n    Alle antwoordende probes hebben dezelfde "
                "ID/DLC-signature."
            )
            print(
                "    Een tokenmatch in een vast responseveld is dan "
                "niet token-specifiek."
            )

        if all(
            not analysis.exact_present
            and not analysis.swapped_present
            for analysis in responses
        ):
            print(
                "    De token wordt in geen enkele response "
                "rechtstreeks teruggevonden."
            )


def mode_sweep(
    bus,
    logger,
    baseline,
    family,
    start,
    end,
    order,
    ad,
    stop_on_hit,
    resume,
    common,
):
    tokens = list(range(start, end + 1))

    if resume:
        done = logger.done_tokens(family, ad)
        before = len(tokens)
        tokens = [token for token in tokens if token not in done]
        print(
            f"[*] Hervatten: {before - len(tokens)} gedaan, "
            f"{len(tokens)} resterend."
        )

    if order == "random":
        random.shuffle(tokens)

    estimate = common["window_s"] + common["settle_s"]
    print(
        f"[*] SWEEP family {family:04X}, AD={ad}: "
        f"{len(tokens)} tokens; minimaal "
        f"~{len(tokens) * estimate / 3600:.2f} uur"
    )
    print("[*] Ctrl-C stopt netjes; --resume hervat later.")

    hits = 0
    started = time.monotonic()

    for index, token in enumerate(tokens, 1):
        if _stop:
            break

        _tx_ok, analysis = do_probe(
            bus,
            logger,
            baseline,
            index,
            family,
            token,
            ad,
            **common,
        )

        if analysis.response:
            hits += 1
            print(
                f"  >>> RESPONSE {token:04X}: "
                f"groups={len(analysis.candidates)}, "
                f"lat={analysis.first_latency_ms:.3f} ms, "
                f"exact={'ja' if analysis.exact_present else 'nee'}, "
                f"swapped="
                f"{'ja' if analysis.swapped_present else 'nee'}"
            )
            if stop_on_hit:
                break

        if index % 50 == 0 or index == len(tokens):
            elapsed = time.monotonic() - started
            rate = index / elapsed if elapsed else 0.0
            eta_minutes = (
                (len(tokens) - index) / rate / 60.0
                if rate
                else 0.0
            )
            print(
                f"  [{index}/{len(tokens)}] responses={hits}, "
                f"{rate * 60:.1f} tokens/min, "
                f"ETA={eta_minutes:.1f} min"
            )

    print(
        f"\n[*] Sweep afgerond of onderbroken. "
        f"Kandidaat-responses: {hits}"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def open_bus(channel, bitrate):
    try:
        return can.Bus(
            interface="pcan",
            channel=channel,
            bitrate=bitrate,
            receive_own_messages=False,
        )
    except TypeError:
        return can.interface.Bus(
            bustype="pcan",
            channel=channel,
            bitrate=bitrate,
        )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "DAB Active Driver Plus CAN "
            "request/response probe v3.1"
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["baseline", "verify", "single", "tokens", "sweep"],
    )
    parser.add_argument("--channel", default="PCAN_USBBUS1")
    parser.add_argument("--bitrate", type=int, default=1_000_000)
    parser.add_argument("--out", default="dab_probe")
    parser.add_argument(
        "--ad",
        default="?",
        help="ingestelde AD-waarde, bijvoorbeeld AUTO, 0, 1, 2 of 3",
    )
    parser.add_argument("--no-raw-beacon", action="store_true")

    parser.add_argument(
        "--family",
        type=parse_int,
        default=DEFAULT_REQ_FAMILY,
    )
    parser.add_argument(
        "--token",
        type=parse_int,
        default=KNOWN_GOOD_TOKEN,
    )
    parser.add_argument(
        "--tokens",
        default="0x0001,0x8000,0xFFFF,0xC82D",
        help="kommagescheiden lijst voor mode=tokens",
    )

    parser.add_argument("--window", type=float, default=0.25)
    parser.add_argument("--quiet", type=float, default=0.05)
    parser.add_argument(
        "--max-extra",
        type=float,
        default=0.50,
        help="maximale verlenging van het responsevenster",
    )
    parser.add_argument("--settle", type=float, default=0.05)
    parser.add_argument("--echo-window-ms", type=float, default=2.0)

    parser.add_argument(
        "--baseline-seconds",
        type=float,
        default=10.0,
        help="baseline vóór actieve probes",
    )
    parser.add_argument(
        "--sigma",
        type=float,
        default=4.0,
        help="drempel voor rate boven baseline",
    )
    parser.add_argument(
        "--min-excess",
        type=int,
        default=2,
        help="minimum aantal frames voor rate-detectie",
    )

    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--start", type=parse_int, default=0x0000)
    parser.add_argument("--end", type=parse_int, default=0xFFFF)
    parser.add_argument(
        "--order",
        choices=["sequential", "random"],
        default="sequential",
    )
    parser.add_argument("--stop-on-hit", action="store_true")
    parser.add_argument("--resume", action="store_true")

    args = parser.parse_args()

    for name, value in (
        ("family", args.family),
        ("token", args.token),
        ("start", args.start),
        ("end", args.end),
    ):
        maximum = 0x1FFF if name == "family" else 0xFFFF
        if not 0 <= value <= maximum:
            parser.error(f"--{name} buiten geldig bereik")

    if args.start > args.end:
        parser.error("--start moet kleiner dan of gelijk aan --end zijn")
    if args.baseline_seconds <= 0:
        parser.error("--baseline-seconds moet groter dan nul zijn")
    if args.window <= 0:
        parser.error("--window moet groter dan nul zijn")
    if args.settle < 0 or args.quiet < 0 or args.max_extra < 0:
        parser.error("--settle, --quiet en --max-extra mogen niet negatief zijn")

    print("=" * 78)
    print(f" DAB probe v{VERSION} | {utcnow()}")
    print(
        f" kanaal={args.channel} "
        f"bitrate={args.bitrate} "
        f"family=0x{args.family:04X} "
        f"AD={args.ad}"
    )
    print(
        f" raw beacon logging="
        f"{'nee' if args.no_raw_beacon else 'ja'}"
    )
    print("=" * 78)

    logger = Logger(
        args.out,
        log_beacon=not args.no_raw_beacon,
    )
    bus = None

    try:
        try:
            bus = open_bus(args.channel, args.bitrate)
        except Exception as exc:
            print(f"\n[!] Kan CAN-bus niet openen: {exc}")
            print(
                "    Sluit PCAN-View en controleer kanaal, "
                "bitrate en driver."
            )
            return 2

        if args.mode == "baseline":
            mode_baseline(
                bus,
                logger,
                args.baseline_seconds,
                args.ad,
            )
            return 0

        baseline = collect_baseline(
            bus,
            logger,
            args.baseline_seconds,
            args.ad,
        )
        if baseline.total_frames == 0:
            print(
                "[!] Geen baselineverkeer ontvangen; "
                "actieve probe wordt afgebroken."
            )
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
                bus,
                logger,
                baseline,
                args.family,
                args.token,
                args.ad,
                args.repeats,
                args.interval,
                common,
            )
        elif args.mode == "single":
            mode_single(
                bus,
                logger,
                baseline,
                args.family,
                args.token,
                args.ad,
                common,
            )
        elif args.mode == "tokens":
            tokens = [
                parse_int(item)
                for item in args.tokens.split(",")
                if item.strip()
            ]
            if not tokens:
                parser.error("--tokens bevat geen tokens")
            if any(not 0 <= token <= 0xFFFF for token in tokens):
                parser.error(
                    "één of meer tokens vallen buiten 0x0000..0xFFFF"
                )
            mode_tokens(
                bus,
                logger,
                baseline,
                args.family,
                tokens,
                args.ad,
                common,
            )
        elif args.mode == "sweep":
            mode_sweep(
                bus,
                logger,
                baseline,
                args.family,
                args.start,
                args.end,
                args.order,
                args.ad,
                args.stop_on_hit,
                args.resume,
                common,
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
            f"\n[*] Logs: "
            f"{args.out}_raw.csv, "
            f"{args.out}_results.csv, "
            f"{args.out}_responses.csv, "
            f"{args.out}_events.csv, "
            f"{args.out}_baseline.csv"
        )


if __name__ == "__main__":
    sys.exit(main())
