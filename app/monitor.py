"""In-memory traffic monitor for WireGuard peers (phase 1: visibility).

Samples the cumulative rx/tx byte counters that ``wg show <tun> dump`` exposes
(see :meth:`PfSenseClient.wg_dump`), differences them over the sample interval to
get per-peer throughput, and keeps a bounded in-memory rolling history. Nothing is
written to the database — samples are high-frequency and disposable, so the
``/api/monitor`` endpoint just serves the current window.

The same per-peer / aggregate rate signal is the input a later phase feeds into
per-peer weight/limit adjustments or WAN autorate (the traffic-shaper work). Keep
this module free of side effects on pfSense so "visibility" can never disrupt the
tunnel.

Counter semantics — the counters are from the *server's* point of view, so we flip
them to the *client's* point of view (which is what the shaper limits):

    rx = bytes the server received from the peer  -> the client's UPLOAD
    tx = bytes the server sent to the peer        -> the client's DOWNLOAD

All rates in the snapshot are **bits per second** (network convention, and it
lines up with the WAN pipe sizes which are configured in Mbit/s).
"""
from __future__ import annotations

import time
from collections import deque


class TrafficMonitor:
    def __init__(
        self,
        *,
        interval: float = 5.0,
        history_len: int = 180,
        peer_history_len: int = 60,
    ):
        # interval is informational (the loop owns the real cadence); history_len is
        # how many aggregate samples to retain, peer_history_len bounds each peer's
        # sparkline series.
        self.interval = interval
        self.history_len = history_len
        self.peer_history_len = peer_history_len

        # pubkey -> (rx, tx, monotonic_ts) of the previous raw sample.
        self._prev: dict[str, tuple[int, int, float]] = {}
        # pubkey -> deque[(wall_ts, up_bps, down_bps)]
        self._peer_hist: dict[str, deque] = {}
        # deque[(wall_ts, up_bps, down_bps)] of the tunnel-wide totals.
        self._agg: deque = deque(maxlen=history_len)

        self._peak_up = 0.0
        self._peak_down = 0.0
        self._last_wall: float | None = None
        self.last_error: str | None = None

    def ingest(
        self,
        live: dict[str, dict],
        *,
        wall: float | None = None,
        mono: float | None = None,
    ) -> None:
        """Fold one ``wg_dump()`` result into the history.

        ``wall``/``mono`` are injectable for tests. Monotonic time drives the rate
        delta (this box has had NTP/clock-drift trouble, so wall time must never
        decide dt); wall time only labels the sample for display.
        """
        wall = time.time() if wall is None else wall
        mono = time.monotonic() if mono is None else mono

        total_up = total_down = 0.0
        seen: set[str] = set()
        for pk, entry in live.items():
            seen.add(pk)
            rx = int(entry.get("rx", 0) or 0)
            tx = int(entry.get("tx", 0) or 0)
            prev = self._prev.get(pk)
            self._prev[pk] = (rx, tx, mono)

            up = down = 0.0
            if prev is not None:
                dt = mono - prev[2]
                if dt > 0:
                    d_rx = rx - prev[0]
                    d_tx = tx - prev[1]
                    # A negative delta means the peer was removed/re-added and the
                    # counter reset — count it as zero rather than a huge spike.
                    up = (d_rx * 8.0 / dt) if d_rx > 0 else 0.0
                    down = (d_tx * 8.0 / dt) if d_tx > 0 else 0.0

            hist = self._peer_hist.setdefault(
                pk, deque(maxlen=self.peer_history_len)
            )
            hist.append((wall, up, down))
            total_up += up
            total_down += down

        # Peers that vanished this round: forget their counter baseline and push a
        # trailing zero so their sparkline decays instead of freezing.
        for pk in list(self._prev.keys()):
            if pk not in seen:
                del self._prev[pk]
                h = self._peer_hist.get(pk)
                if h is not None:
                    h.append((wall, 0.0, 0.0))

        # Drop peers that are both absent now and idle across the whole window, so
        # the map doesn't grow without bound as devices come and go.
        for pk in list(self._peer_hist.keys()):
            if pk in seen:
                continue
            h = self._peer_hist[pk]
            if not h or all(s[1] == 0.0 and s[2] == 0.0 for s in h):
                del self._peer_hist[pk]

        self._agg.append((wall, total_up, total_down))
        self._peak_up = max(self._peak_up, total_up)
        self._peak_down = max(self._peak_down, total_down)
        self._last_wall = wall

    def snapshot(
        self,
        *,
        names: dict[str, str] | None = None,
        pipe_up_mbit: float = 0.0,
        pipe_down_mbit: float = 0.0,
    ) -> dict:
        """Serializable current view for the API/UI.

        ``names`` maps pubkey -> display name (from the device registry). The WAN
        pipe sizes (Mbit/s, 0 = unknown) drive the "share of link" bars — this is
        the honest way to show pressure without reading WAN interface counters yet.
        """
        names = names or {}

        peers = []
        for pk, hist in self._peer_hist.items():
            if not hist:
                continue
            _, up, down = hist[-1]
            peers.append({
                "public_key": pk,
                "name": names.get(pk) or "(unnamed peer)",
                "up": round(up),
                "down": round(down),
                "up_series": [round(s[1]) for s in hist],
                "down_series": [round(s[2]) for s in hist],
            })
        # Stable order (name, then key) so rows don't reshuffle every poll — a
        # throughput sort would make the table jump around on the live dashboard.
        peers.sort(key=lambda p: (p["name"].lower(), p["public_key"]))

        cur_wall, cur_up, cur_down = (
            self._agg[-1] if self._agg else (self._last_wall, 0.0, 0.0)
        )

        pipe = None
        if pipe_up_mbit or pipe_down_mbit:
            up_cap = pipe_up_mbit * 1_000_000
            down_cap = pipe_down_mbit * 1_000_000
            pipe = {
                "up_mbit": pipe_up_mbit,
                "down_mbit": pipe_down_mbit,
                "up_used_pct": round(100 * cur_up / up_cap, 1) if up_cap else None,
                "down_used_pct": round(100 * cur_down / down_cap, 1) if down_cap else None,
            }

        return {
            "enabled": True,
            "sampled_at": cur_wall,
            "interval": self.interval,
            "peers": peers,
            "aggregate": {
                "up": round(cur_up),
                "down": round(cur_down),
                "peak_up": round(self._peak_up),
                "peak_down": round(self._peak_down),
                "series": [
                    {"t": s[0], "up": round(s[1]), "down": round(s[2])}
                    for s in self._agg
                ],
            },
            "pipe": pipe,
            "last_error": self.last_error,
        }
