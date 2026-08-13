"""pfSense traffic-shaper client — the "LAN priority over WireGuard" scheme.

This is deliberately separate from ``pfsense.py``: shaping is a pfSense QoS
concern, only indirectly related to WireGuard peer management, so it gets its own
client and its own ``/api/shaper`` surface.

What it manages (and ONLY this — it never rewrites objects it didn't create):

  Two limiters, one per direction, each a single shared pipe with two weighted
  child queues::

      wgweb_down  (bw = WAN download Mbit/s, sched wf2q+)
        ├─ wgweb_down_lan   weight = LAN   (e.g. 100)
        └─ wgweb_down_wg    weight = WG    (e.g. 5)
      wgweb_up    (bw = WAN upload  Mbit/s, sched wf2q+)
        ├─ wgweb_up_lan     weight = LAN
        └─ wgweb_up_wg      weight = WG

``sched = wf2q+`` is what makes the weights bite: fq_codel would ignore them and
flow-hash instead. Queues use ``aqm = droptail`` — not codel — because the REST
package's queue model has a broken ``ecn`` condition that references a ``sched``
field the queue doesn't have, and every other AQM trips it (see _create_queue).
Weights only matter under congestion — when local traffic is idle, WG still gets
the whole pipe.

Attachment is per-rule (:meth:`assign_rule`): pfSense shaping lives on firewall
rules (per-interface, on an interface group, or source-aliased), so the UI shows
the real status — exactly which rules carry our limiters — and lets the user set
Local/WG on any rule or clear it. The API has no floating "match" action, so a
rule is the finest honest unit of control.

Direction convention on a rule (see the pfSense limiter docs):
  In pipe  (dnpipe)  = traffic entering the firewall in the rule's match direction
  Out pipe (pdnpipe) = the reverse

Which of those is "upload" depends on WHICH SIDE of the firewall the rule's
interface sits on, and getting it wrong silently disables shaping:

  LAN-side rule (lan, opt1, a LAN interface group, ...)
      In  = client -> internet          = WAN upload    -> *_up_*
      Out = internet -> client          = WAN download  -> *_down_*

  Tunnel-side rule (the WireGuard interface, e.g. tun_wg0/opt4)
      In  = peer -> us; it reached us over the WAN inbound = WAN download -> *_down_*
      Out = us -> peer; it leaves over the WAN outbound    = WAN upload   -> *_up_*

  WAN-side rule (an inbound port-forward / reverse-proxy pass rule on wan)
      In  = internet -> us                                = WAN download -> *_down_*
      Out = us -> internet                                = WAN upload   -> *_up_*

So tunnel AND WAN rules are both REVERSED relative to a LAN rule. Applying the LAN
mapping to them puts internet-bound traffic (which consumes the scarce WAN uplink)
into the much larger download pipe, where it is effectively never throttled --
a remote peer can then saturate the uplink no matter what the queue weights say.
:meth:`assign_rule` resolves this per rule via :meth:`_rule_is_reversed`.

Why WAN rules matter at all: a pf state pins its limiters at creation time and the
reply direction is never re-evaluated, so a flow the *internet* opened (a remote
client streaming off a LAN server via the reverse proxy) is shaped only if the WAN
rule that admitted it carries a queue. Leave those rules bare and that traffic sits
outside dummynet entirely -- and since wf2q+ can only arbitrate flows inside the
same pipe, the WireGuard queue has nothing to yield to and takes the whole uplink
no matter how low its weight is.
"""
from __future__ import annotations

import asyncio
import logging

import httpx

from .pfsense import PfSenseAPIError

logger = logging.getLogger("shaper")

# Object names this app owns. Anything not matching these is left untouched.
LIMITER_DOWN = "wgweb_down"
LIMITER_UP = "wgweb_up"
_LIMITERS = (LIMITER_DOWN, LIMITER_UP)

# Per-host queue masking. Without a mask a queue is ONE shared FIFO: a single bulk
# transfer keeps it permanently full and everything else sharing it (pings, DNS,
# SSH) is tail-dropped. Measured 2026-08-12 — an offsite backup pinned the up pipe
# at its 92 Mbit ceiling and ICMP to that peer lost ~20%, while the same host pinged
# from pfSense (which bypasses these rules, and so the queue) lost 0/150. Masking
# gives each host its own dynamic sub-queue of the same pipe, so flows share the
# bandwidth instead of queueing behind each other.
#
# The mask has to key on the LAN-side host in BOTH directions, so it differs per
# limiter:
#     *_up_*    carries LAN host -> peer/internet   -> LAN host is the SOURCE
#     *_down_*  carries peer/internet -> LAN host   -> LAN host is the DESTINATION
#
# This belongs on the QUEUES only. Masking the parent pipe would hand every host its
# own full-bandwidth pipe and remove the WAN cap altogether.
QUEUE_MASKBITS = 32
# dummynet's default queue depth (~50 slots) is too shallow and tail-drops bursts.
QUEUE_QLIMIT = 300

# The three shaping classes, in priority order. "lan" and "wg" split the pipe by the
# user's ratio dial; "bulk" is a fixed low weight for background site-to-site transfer
# (offsite backups, file sync) that should yield to everything else.
#
# Bulk exists because backups and interactive VPN use have opposite needs: a backup
# only cares about finishing, a phone on VPN cares about latency, and at equal weight
# the backup wins simply by always having more to send. Weights are relative and only
# apply under contention, so an idle link still lets a backup run at full pipe speed.
SIDE_LAN = "lan"
SIDE_WG = "wg"
SIDE_BULK = "bulk"
SIDES = (SIDE_LAN, SIDE_WG, SIDE_BULK)
# Not user-tunable: the ratio dial governs lan-vs-wg, and bulk deliberately sits below
# both. wf2q+ accepts 1-100; 5 against a 70/30 split is ~5% under full contention.
BULK_WEIGHT = 5


def queue_mask(limiter: str) -> str:
    """Which address a limiter's child queues key their sub-queues on."""
    return "srcaddress" if limiter == LIMITER_UP else "dstaddress"


def q_name(limiter: str, side: str) -> str:
    """Queue name for a limiter + side ("lan" | "wg" | "bulk")."""
    return f"{limiter}_{side}"


def side_pipes(side: str, *, reversed_dir: bool = False) -> dict[str, str]:
    """The In/Out pipe (dnpipe/pdnpipe) queue names for a side.

    side "lan" -> Local queues, "wg" -> WireGuard queues, "bulk" -> background
    site-to-site queues, "none" -> clear.

    ``reversed_dir`` says the rule lives on the WireGuard or the WAN interface, where
    traffic flows the opposite way relative to a LAN rule, so In/Out swap (see the
    module docstring).
    """
    if side in SIDES:
        in_pipe, out_pipe = LIMITER_UP, LIMITER_DOWN
        if reversed_dir:
            in_pipe, out_pipe = LIMITER_DOWN, LIMITER_UP
        return {"dnpipe": q_name(in_pipe, side), "pdnpipe": q_name(out_pipe, side)}
    # null (not "") is how the API clears a pipe — the field rejects empty strings.
    return {"dnpipe": None, "pdnpipe": None}


def _our_queue_names() -> set[str]:
    return {q_name(lim, side) for lim in _LIMITERS for side in SIDES}


# Address types that only ever describe an uplink, used to spot secondary WANs.
# The primary WAN is always id "wan"; extra ones are optN and are told apart by
# either a dynamic uplink type or a static gateway. (A DHCP WAN reports gateway ""
# because its gateway is dynamic, so the type check has to come first.)
_WAN_ADDR_TYPES = {"dhcp", "pppoe", "pptp", "l2tp", "ppp"}


def _is_wan_iface(iface: dict) -> bool:
    """Whether a pfSense interface object is an internet uplink."""
    if iface.get("id") == "wan":
        return True
    if iface.get("typev4") in _WAN_ADDR_TYPES or iface.get("typev6") in _WAN_ADDR_TYPES:
        return True
    return bool(iface.get("gateway") or iface.get("gatewayv6"))


class ShaperClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        tunnel: str,
        verify_tls: bool = False,
        timeout: float = 15.0,
    ):
        # The WireGuard device (e.g. "tun_wg0"). Rules on the pfSense interface
        # backed by it need the reversed pipe orientation — see side_pipes().
        self._tunnel = tunnel
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"X-API-Key": api_key, "Accept": "application/json"},
            verify=verify_tls,
            timeout=timeout,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    # ---- low-level (same envelope handling as PfSenseClient) ----
    async def _request(self, method: str, path: str, **kwargs) -> dict:
        try:
            resp = await self._client.request(method, path, **kwargs)
        except httpx.HTTPError as e:
            logger.warning("shaper transport error on %s %s: %s", method, path, e)
            raise PfSenseAPIError(f"Could not reach pfSense API: {e}") from e
        try:
            body = resp.json()
        except ValueError:
            body = {}
        if resp.status_code >= 400 or (body.get("code") and body["code"] >= 400):
            msg = body.get("message") or f"HTTP {resp.status_code}"
            logger.warning("shaper API error on %s %s: %s", method, path, msg)
            raise PfSenseAPIError(msg, status_code=resp.status_code)
        return body

    # ---- limiters ----
    async def list_limiters(self) -> list[dict]:
        body = await self._request(
            "GET", "/api/v2/firewall/traffic_shaper/limiters", params={"limit": 0}
        )
        data = body.get("data") or []
        return data if isinstance(data, list) else []

    async def get_limiter(self, name: str) -> dict | None:
        for lim in await self.list_limiters():
            if lim.get("name") == name:
                return lim
        return None

    async def _create_limiter(self, payload: dict) -> dict:
        body = await self._request(
            "POST", "/api/v2/firewall/traffic_shaper/limiter", json=payload
        )
        return body.get("data") or {}

    async def _patch_bandwidth(self, parent_id: int, bw_id: int, bw_mbit: int) -> None:
        await self._request(
            "PATCH",
            "/api/v2/firewall/traffic_shaper/limiter/bandwidth",
            json={"parent_id": parent_id, "id": bw_id, "bw": bw_mbit, "bwscale": "Mb"},
        )

    async def _patch_queue_weight(self, parent_id: int, q_id: int, weight: int) -> None:
        await self._request(
            "PATCH",
            "/api/v2/firewall/traffic_shaper/limiter/queue",
            json={"parent_id": parent_id, "id": q_id, "weight": weight},
        )

    async def _create_queue(
        self, parent_id: int, limiter: str, name: str, weight: int
    ) -> None:
        # aqm MUST be "droptail": the package's queue model has an `ecn` field whose
        # condition references a non-existent `sched` field, and any AQM in
        # [codel,pie,red,gred] trips that broken condition. droptail avoids it.
        # Queues are created one at a time (not inline in the limiter) so each gets a
        # distinct auto-assigned number instead of colliding on 0.
        await self._request(
            "POST",
            "/api/v2/firewall/traffic_shaper/limiter/queue",
            json={"parent_id": parent_id, "name": name, "enabled": True,
                  "aqm": "droptail", "mask": queue_mask(limiter),
                  "maskbits": QUEUE_MASKBITS, "qlimit": QUEUE_QLIMIT,
                  "weight": weight},
        )

    async def _patch_queue_shape(
        self, parent_id: int, limiter: str, q_id: int, weight: int
    ) -> None:
        """Set an existing queue's weight and (re)assert its mask + qlimit.

        Deployments created before per-host masking have ``mask: none`` and no
        ``qlimit``; asserting both here repairs them in place on the next
        ensure_scheme() instead of needing the limiters rebuilt.
        """
        await self._request(
            "PATCH",
            "/api/v2/firewall/traffic_shaper/limiter/queue",
            json={"parent_id": parent_id, "id": q_id, "weight": weight,
                  "mask": queue_mask(limiter), "maskbits": QUEUE_MASKBITS,
                  "qlimit": QUEUE_QLIMIT},
        )

    async def delete_limiter(self, limiter_id: int) -> None:
        await self._request(
            "DELETE",
            "/api/v2/firewall/traffic_shaper/limiter",
            params={"id": limiter_id},
        )

    # ---- interfaces + firewall rules ----
    async def list_interfaces(self) -> list[dict]:
        body = await self._request("GET", "/api/v2/interfaces", params={"limit": 0})
        data = body.get("data") or []
        return data if isinstance(data, list) else []

    async def list_rules(self) -> list[dict]:
        body = await self._request(
            "GET", "/api/v2/firewall/rules", params={"limit": 0}
        )
        data = body.get("data") or []
        return data if isinstance(data, list) else []

    async def reversed_iface_ids(self) -> set[str]:
        """Interface ids whose rules run reversed relative to a LAN rule.

        That is our WireGuard device's ids (e.g. {"opt4"}) plus every WAN-typed
        interface. Both sit on the far side of the firewall from a LAN client, so
        their In/Out pipes swap — see the module docstring.
        """
        ids = set()
        for i in await self.list_interfaces():
            iid = i.get("id")
            if not iid:
                continue
            if i.get("if") == self._tunnel or _is_wan_iface(i):
                ids.add(iid)
        return ids

    @staticmethod
    def _rule_ifaces(rule: dict) -> list[str]:
        ifs = rule.get("interface")
        return ifs if isinstance(ifs, list) else [ifs] if ifs else []

    def _rule_is_reversed(self, rule: dict, reversed_ids: set[str]) -> bool:
        """True if this rule's In/Out pipes must swap (WireGuard- or WAN-side).

        Only direct interface ids count. An interface *group* is left as LAN-side:
        the group's members aren't in the rule object, and a group mixing the tunnel
        or a WAN with LAN interfaces has no single correct orientation anyway.
        """
        return any(t in reversed_ids for t in self._rule_ifaces(rule))

    async def patch_rule(
        self,
        rule_id: int,
        *,
        dnpipe: str | None,
        pdnpipe: str | None,
        rule_type: str | None = None,
    ) -> None:
        # A PATCH is partial but still validated against the whole model, and `type`
        # is required. Rules auto-generated by a NAT port forward come back from the
        # API with no `type` at all, so echoing what we read would resend nothing and
        # the write fails with "Field `type` is required" — hence the "pass" default.
        # Those rules are always pass rules, and they are exactly the ones carrying
        # inbound-initiated traffic (a port-forwarded media server), so they have to
        # be attachable or that traffic can never be shaped.
        await self._request(
            "PATCH",
            "/api/v2/firewall/rule",
            # None -> JSON null, which clears the pipe (the field rejects "").
            json={
                "id": rule_id,
                "type": rule_type or "pass",
                "dnpipe": dnpipe,
                "pdnpipe": pdnpipe,
            },
        )

    async def apply(self) -> dict:
        """Apply pending changes, waiting for the shaper subsystem to clear.

        The first POST often comes back ``applied: false`` with the "shaper"
        subsystem still pending — limiter edits are reloaded on a later pass — so a
        single call can leave new bandwidth/weights staged but not live. Re-POST
        until it reports done, pausing between tries — back-to-back calls with no
        gap keep returning "pending"; the reload needs a moment to finish.
        """
        data: dict = {}
        for attempt in range(4):
            if attempt:
                await asyncio.sleep(2)
            body = await self._request("POST", "/api/v2/firewall/apply", json={})
            data = body.get("data") or {}
            if data.get("applied") and not data.get("pending_subsystems"):
                return data
        if not data.get("applied"):
            logger.warning(
                "firewall apply still pending after retries: %s",
                data.get("pending_subsystems"),
            )
        return data

    # ---- high-level orchestration ----
    @staticmethod
    def _limiter_payload(name: str, bw_mbit: int) -> dict:
        # One shared pipe (mask none), scheduler wf2q+ so the child queue weights
        # actually take effect. Queues are added separately (see _create_queue).
        return {
            "name": name,
            "enabled": True,
            "mask": "none",
            "aqm": "droptail",
            "sched": "wf2q+",
            "bandwidth": [{"bw": bw_mbit, "bwscale": "Mb", "bwsched": "none"}],
        }

    async def ensure_scheme(
        self, *, down_mbit: int, up_mbit: int, lan_weight: int, wg_weight: int
    ) -> None:
        """Create the limiters if absent, else update their bandwidth + weights.

        Idempotent. Creates the pipe (with bandwidth), then each queue in its own
        POST. On an existing limiter it updates bandwidth in place, updates the
        weight of any queue already there, and creates any queue that's missing —
        never deleting/replacing queues (that could break rules referencing them).
        """
        weights = {SIDE_LAN: lan_weight, SIDE_WG: wg_weight, SIDE_BULK: BULK_WEIGHT}
        for name, bw in ((LIMITER_DOWN, down_mbit), (LIMITER_UP, up_mbit)):
            existing = await self.get_limiter(name)
            if existing is None:
                await self._create_limiter(self._limiter_payload(name, bw))
                existing = await self.get_limiter(name) or {}

            parent_id = existing["id"]
            for bwobj in existing.get("bandwidth") or []:
                await self._patch_bandwidth(parent_id, bwobj["id"], bw)

            by_name = {q.get("name"): q for q in existing.get("queue") or []}
            for side, weight in weights.items():
                qn = q_name(name, side)
                q = by_name.get(qn)
                if q is None:
                    await self._create_queue(parent_id, name, qn, weight)
                else:
                    await self._patch_queue_shape(parent_id, name, q["id"], weight)

    async def set_ratio(self, *, lan_weight: int, wg_weight: int) -> None:
        """Update only the queue weights on the existing limiters."""
        for name in _LIMITERS:
            lim = await self.get_limiter(name)
            if lim is not None:
                await self._apply_weights(lim, lan_weight, wg_weight)

    async def _apply_weights(self, limiter: dict, lan_weight: int, wg_weight: int) -> None:
        # The ratio dial governs lan-vs-wg only; the bulk queue keeps BULK_WEIGHT and
        # is deliberately left untouched here.
        parent_id = limiter["id"]
        for q in limiter.get("queue") or []:
            if q.get("name", "").endswith(f"_{SIDE_LAN}"):
                await self._patch_queue_weight(parent_id, q["id"], lan_weight)
            elif q.get("name", "").endswith(f"_{SIDE_WG}"):
                await self._patch_queue_weight(parent_id, q["id"], wg_weight)

    async def assign_rule(self, rule_id: int, side: str) -> None:
        """Point one rule's pipes at a side's queues ("lan"/"wg"), or clear ("none").

        Rule-level control is the honest model: pfSense shaping lives on firewall
        rules (which may be per-interface, on an interface group, or source-aliased),
        so the UI shows and edits exactly the rules that carry our limiters.
        """
        if side not in (*SIDES, "none"):
            raise PfSenseAPIError(f"Unknown side {side!r}")

        rule = next((r for r in await self.list_rules() if r.get("id") == rule_id), None)
        if rule is None:
            raise PfSenseAPIError(f"No such firewall rule: {rule_id}")

        if side == "none":
            # Refuse to clear a rule carrying someone else's limiter.
            ours = _our_queue_names()
            dn, pdn = rule.get("dnpipe") or "", rule.get("pdnpipe") or ""
            if (dn or pdn) and dn not in ours and pdn not in ours:
                raise PfSenseAPIError("Rule carries a different limiter; not clearing it.")
            await self.patch_rule(
                rule_id, rule_type=rule.get("type"), **side_pipes("none")
            )
            return

        rev = self._rule_is_reversed(rule, await self.reversed_iface_ids())
        await self.patch_rule(
            rule_id,
            rule_type=rule.get("type"),
            **side_pipes(side, reversed_dir=rev),
        )

    async def resync_orientation(self) -> list[dict]:
        """Re-point every rule already carrying our queues at the correct pipes.

        Repairs rules attached before the orientation was interface-aware, where a
        tunnel- or WAN-side rule got the LAN mapping and so was never really shaped.
        Keeps each rule's existing side; only the In/Out assignment can change.
        Returns the rules that were actually changed.
        """
        ours_by_side = {
            s: {q_name(lim, s) for lim in _LIMITERS} for s in SIDES
        }
        reversed_ids = await self.reversed_iface_ids()
        changed = []
        for rule in await self.list_rules():
            dn, pdn = rule.get("dnpipe") or "", rule.get("pdnpipe") or ""
            side = next(
                (s for s, names in ours_by_side.items() if dn in names or pdn in names),
                None,
            )
            if side is None:
                continue
            want = side_pipes(side, reversed_dir=self._rule_is_reversed(rule, reversed_ids))
            if want["dnpipe"] == dn and want["pdnpipe"] == pdn:
                continue
            await self.patch_rule(rule["id"], rule_type=rule.get("type"), **want)
            changed.append({
                "id": rule["id"],
                "descr": rule.get("descr") or "",
                "side": side,
                "from": {"dnpipe": dn, "pdnpipe": pdn},
                "to": want,
            })
        return changed

    async def teardown(self) -> None:
        """Detach any rules pointing at our queues, then delete our limiters."""
        ours = _our_queue_names()
        for rule in await self.list_rules():
            if rule.get("dnpipe") in ours or rule.get("pdnpipe") in ours:
                rid = rule.get("id")
                if rid is not None:
                    await self.patch_rule(
                        rid, rule_type=rule.get("type"), dnpipe=None, pdnpipe=None
                    )
        for name in _LIMITERS:
            lim = await self.get_limiter(name)
            if lim is not None:
                await self.delete_limiter(lim["id"])

    async def state(self) -> dict:
        """Current scheme state + real per-rule shaping status, for the UI."""
        limiters = {lim.get("name"): lim for lim in await self.list_limiters()}
        down = limiters.get(LIMITER_DOWN)
        up = limiters.get(LIMITER_UP)
        configured = down is not None and up is not None

        def _weights(lim: dict | None) -> dict:
            out = {"lan": None, "wg": None}
            for q in (lim or {}).get("queue") or []:
                if q.get("name", "").endswith("_lan"):
                    out["lan"] = q.get("weight")
                elif q.get("name", "").endswith("_wg"):
                    out["wg"] = q.get("weight")
            return out

        def _bw(lim: dict | None) -> int | None:
            for b in (lim or {}).get("bandwidth") or []:
                return b.get("bw")
            return None

        ours_by_side = {s: {q_name(lim, s) for lim in _LIMITERS} for s in SIDES}
        # Friendly names for interface tokens (physical); groups keep their raw name.
        ifaces = await self.list_interfaces()
        descr = {i.get("id"): i.get("descr") for i in ifaces}
        reversed_ids = {
            i["id"]
            for i in ifaces
            if i.get("id") and (i.get("if") == self._tunnel or _is_wan_iface(i))
        }

        rules = []
        misoriented = 0
        for r in await self.list_rules():
            # A rule auto-generated by a NAT port forward reports no `type` at all;
            # it is nonetheless a pass rule, and it is the only place inbound-
            # initiated traffic (a port-forwarded media server) can be shaped, so
            # treat a missing type as "pass" rather than hiding the rule.
            if (r.get("type") or "pass") != "pass" or r.get("floating"):
                continue
            dn, pdn = r.get("dnpipe") or "", r.get("pdnpipe") or ""
            side = next(
                (s for s, names in ours_by_side.items() if dn in names or pdn in names),
                None,
            )
            ifs = self._rule_ifaces(r)
            rev = self._rule_is_reversed(r, reversed_ids)
            # Shaped rules whose pipes don't match their interface orientation are
            # attached but not actually throttling — surfaced so the UI can say so.
            oriented = True
            if side is not None:
                want = side_pipes(side, reversed_dir=rev)
                oriented = want["dnpipe"] == dn and want["pdnpipe"] == pdn
                misoriented += not oriented
            rules.append({
                "id": r.get("id"),
                "interface": ifs,
                "interface_label": ", ".join(descr.get(t, t) for t in ifs) or "—",
                "descr": r.get("descr") or "",
                "protocol": r.get("protocol"),
                "side": side,   # "lan" | "wg" | None
                "reversed_dir": rev,
                "oriented": oriented,
                # A limiter that isn't ours — flagged so the UI won't offer to clear it.
                "other_limiter": bool((dn or pdn) and side is None),
            })
        rules.sort(key=lambda x: (x["side"] is None, x["interface_label"].lower()))
        shaped_counts = {
            "lan": sum(1 for r in rules if r["side"] == "lan"),
            "wg": sum(1 for r in rules if r["side"] == "wg"),
        }

        return {
            "enabled": True,
            "configured": configured,
            "down": {
                "enabled": (down or {}).get("enabled"),
                "bw_mbit": _bw(down),
                "weights": _weights(down),
            },
            "up": {
                "enabled": (up or {}).get("enabled"),
                "bw_mbit": _bw(up),
                "weights": _weights(up),
            },
            "rules": rules,
            "shaped_counts": shaped_counts,
            "misoriented_count": misoriented,
        }
