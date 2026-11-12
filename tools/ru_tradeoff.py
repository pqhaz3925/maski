#!/usr/bin/env python3
"""Coarser «Российские сайты напрямую» lists and what each costs (docs/followups-2026-11-11.md).

usage: ru_tradeoff.py <ru4.txt> [geoip.dat] [--counts 15000,10000,5000,2000,1000,500] [--write <dir>]

Two ways to shrink the list of excluded routes, from the same geoip:ru prefixes:
  drop  - keep the N largest prefixes; the dropped (small) ones then go through the tunnel.
  merge - greedy supernets: repeatedly replace the prefixes under a common supernet by that
          supernet, cheapest first (fewest non-RU addresses added per route saved); those non-RU
          addresses then go direct.
For each N: Russian addresses still direct (share), non-RU addresses sent direct, and with
geoip.dat which countries those non-RU addresses belong to (the rest is in no country's list).
--write <dir> writes drop-<N>.txt / merge-<N>.txt.
"""
import argparse, bisect, heapq, ipaddress, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def load(path):
    out = []
    for l in open(path):
        l = l.strip()
        if l and not l.startswith("#"):
            n = ipaddress.IPv4Network(l)
            out.append((int(n.network_address), n.prefixlen))
    return sorted(out)


def size(plen):
    return 1 << (32 - plen)


def covered(intervals_start, intervals_end, cum, lo, hi):
    """Addresses of a sorted, disjoint interval list inside [lo, hi)."""
    i = bisect.bisect_right(intervals_end, lo)
    tot = 0
    while i < len(intervals_start) and intervals_start[i] < hi:
        tot += min(hi, intervals_end[i]) - max(lo, intervals_start[i])
        i += 1
    return tot


def drop(ru, n):
    keep = sorted(ru, key=lambda x: (x[1], x[0]))[:n]
    return sorted(keep)


def merge_snapshots(ru, counts, forbid=None):
    """Greedy supernet merge; returns {count: list of (addr, plen)} for each requested count.
    forbid: merged intervals no supernet may cover (e.g. blocked or foreign service addresses)."""
    # Trie over every ancestor of every prefix: node = (addr, plen).
    cnt, cov = {}, {}
    for a, l in ru:
        s = size(l)
        for pl in range(l - 1, -1, -1):
            node = (a & ~(size(pl) - 1) & 0xFFFFFFFF, pl)
            cnt[node] = cnt.get(node, 0) + 1
            cov[node] = cov.get(node, 0) + s
    ver = {}
    heap = []

    def push(node):
        c = cnt.get(node, 0)
        if c >= 2 and not (forbid and covered(forbid[0], forbid[1], None, node[0], node[0] + size(node[1]))):
            v = ver.get(node, 0) + 1
            ver[node] = v
            cost = (size(node[1]) - cov[node]) / (c - 1)
            heapq.heappush(heap, (cost, -node[1], node, v))

    for node in list(cnt):
        push(node)
    alive = sorted(ru)
    total = len(alive)
    want = sorted(counts, reverse=True)
    snaps = {}
    merged = set()

    def under_merged(node):
        a, l = node
        return any((a & ~(size(pl) - 1) & 0xFFFFFFFF, pl) in merged for pl in range(l - 1, -1, -1))

    while want and heap:
        while want and total <= want[0]:
            snaps[want.pop(0)] = list(alive)
        if not want:
            break
        cost, _, node, v = heapq.heappop(heap)
        if ver.get(node) != v or cnt.get(node, 0) < 2 or under_merged(node):
            continue
        a, l = node
        lo, hi = a, a + size(l)
        i = bisect.bisect_left(alive, (lo, -1))
        j = bisect.bisect_left(alive, (hi, -1))
        alive[i:j] = [node]
        merged.add(node)
        dc = 1 - cnt[node]
        dv = size(l) - cov[node]
        total += dc
        cnt[node] = 0
        cov[node] = size(l)
        for pl in range(l - 1, -1, -1):
            anc = (a & ~(size(pl) - 1) & 0xFFFFFFFF, pl)
            cnt[anc] += dc
            cov[anc] += dv
            push(anc)
    while want:
        snaps[want.pop(0)] = sorted(alive)
    return snaps


def intervals(prefixes):
    iv = sorted((a, a + size(l)) for a, l in prefixes)
    out = []
    for s, e in iv:
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return [x[0] for x in out], [x[1] for x in out]


def lists(geoip):
    """Every named IPv4 list of geoip.dat except RU (the source), as merged intervals."""
    from geoip_ru import fields
    data = open(geoip, "rb").read()
    res = {}
    for f, _, entry in fields(data):
        if f != 1:
            continue
        code, nets = None, []
        for g, _, v in fields(entry):
            if g == 1:
                code = v.decode()
            elif g == 2:
                ip, prefix = b"", 0
                for h, _, w in fields(v):
                    if h == 1:
                        ip = w
                    elif h == 2:
                        prefix = w
                if len(ip) == 4:
                    nets.append((int.from_bytes(ip, "big"), prefix))
        code = (code or "").upper()
        if nets and code not in ("RU", "IN-RU") and not code.startswith("IN-CN"):
            res[code] = intervals(nets)
    return res


def inter(a, b):
    """Addresses in both of two merged interval lists."""
    (as_, ae), (bs, be) = a, b
    i = j = tot = 0
    while i < len(as_) and j < len(bs):
        lo, hi = max(as_[i], bs[j]), min(ae[i], be[j])
        if lo < hi:
            tot += hi - lo
        if ae[i] < be[j]:
            i += 1
        else:
            j += 1
    return tot


def minus(a, b):
    """a minus b, both merged interval lists."""
    out_s, out_e = [], []
    j = 0
    bs, be = b
    for s, e in zip(*a):
        cur = s
        while j < len(bs) and be[j] <= cur:
            j += 1
        k = j
        while k < len(bs) and bs[k] < e:
            if bs[k] > cur:
                out_s.append(cur); out_e.append(bs[k])
            cur = max(cur, be[k])
            k += 1
        if cur < e:
            out_s.append(cur); out_e.append(e)
    return out_s, out_e


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ru"); ap.add_argument("geoip", nargs="?")
    ap.add_argument("--counts", default="15000,10000,5000,2000,1000,500")
    ap.add_argument("--write")
    a = ap.parse_args()
    ru = load(a.ru)
    counts = [int(x) for x in a.counts.split(",")]
    R = intervals(ru)
    ru_total = sum(e - s for s, e in zip(*R))
    L = lists(a.geoip) if a.geoip else {}
    print(f"RU: {len(ru)} prefixes, {ru_total} addresses ({ru_total / 2**24:.2f} x /8)")
    by_len = {}
    for _, l in ru:
        by_len[l] = by_len.get(l, 0) + 1
    print("prefix lengths:", " ".join(f"/{l}:{n}" for l, n in sorted(by_len.items())))
    if "BLACKLIST-RU" in L:
        print(f"shipped list: {inter(R, L['BLACKLIST-RU'])} addresses of BLACKLIST-RU already go direct")
    print()
    cands = [("as shipped", len(ru), ru)]
    cands += [("drop", n, drop(ru, n)) for n in counts]
    snaps = merge_snapshots(ru, counts)
    cands += [("merge", n, snaps[n]) for n in counts]
    if L:
        # merge-safe: never cover a non-RU address that is in any named list (blocked in Russia, Telegram,
        # Google, Cloudflare, ...): those must keep going through the tunnel.
        allf = [(x, y) for k, (xs, ys) in L.items() if k != "PRIVATE" for x, y in zip(xs, ys)]
        allf.sort()
        m = []
        for x, y in allf:
            if m and x <= m[-1][1]:
                m[-1][1] = max(m[-1][1], y)
            else:
                m.append([x, y])
        FX = minus(([x[0] for x in m], [x[1] for x in m]), R)
        safe = merge_snapshots(ru, counts, FX)
        seen = set()
        for n in counts:
            if len(safe[n]) not in seen:
                seen.add(len(safe[n]))
                cands.append(("merge-safe", n, safe[n]))
        # Hybrid: the safe merge down to 10 000 routes (few non-RU addresses), then drop the smallest.
        base = safe[10000] if 10000 in safe else min(safe.values(), key=len)
        cands += [("merge-safe+drop", n, drop(base, n)) for n in counts if n < len(base)]
    print("| way | routes | RU addresses direct | RU through the tunnel | non-RU direct | of which in BLACKLIST-RU | non-RU direct in named lists |")
    print("|---|---|---|---|---|---|---|")
    for way, n, lst in cands:
        D = intervals(lst)
        ru_dir = inter(D, R)
        F = minus(D, R)
        foreign = sum(e - s for s, e in zip(*F))
        bl = inter(F, L["BLACKLIST-RU"]) if "BLACKLIST-RU" in L else 0
        named = []
        for k, v in L.items():
            if k.startswith("BLACKLIST"):
                continue
            c = inter(F, v)
            if c:
                named.append((k, c))
        named.sort(key=lambda x: -x[1])
        fmt = lambda v: f"{v / 1e6:.2f} M" if v >= 100_000 else f"{v / 1e3:.1f} k" if v >= 1000 else str(v)
        print(f"| {way} | {len(lst)} | {ru_dir / ru_total * 100:.2f} % | {fmt(ru_total - ru_dir)} | {fmt(foreign)} | {fmt(bl)} | "
              + (", ".join(f"{k} {fmt(v)}" for k, v in named[:6]) or "-") + " |")
        if a.write and way != "as shipped":
            os.makedirs(a.write, exist_ok=True)
            with open(os.path.join(a.write, f"{way}-{n}.txt"), "w") as f:
                for x, l in lst:
                    f.write(f"{ipaddress.IPv4Address(x)}/{l}\n")


if __name__ == "__main__":
    main()
