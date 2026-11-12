#!/usr/bin/env python3
"""The shipped «Российские сайты напрямую» list (ios/Tunnel/ru4.txt): build it and check it.

usage:
  ru_list.py build <geoip.dat> <riswhoisdump.IPv4.gz> [--count 10000] [--asn tools/ru_list_asn.txt] > ios/Tunnel/ru4.txt
  ru_list.py check <geoip.dat> <riswhoisdump.IPv4.gz> <list> [--old <list>...] [--count 10000] [--asn ...]

Source: geoip:ru of xray's geoip.dat (~20k prefixes, see ios/README.md). Every route costs blackout
time when iOS applies the list (≈ 0.2 s + 7.5 ms × (thousands of routes)², docs/followups-2026-11-11.md),
so the list is shrunk to --count routes by greedy supernets (variant (b') of tools/ru_tradeoff.py):
repeatedly replace the prefixes under a common supernet by that supernet, cheapest first (fewest
non-RU addresses added per route saved), but never a supernet that covers a forbidden address:
  - every other list of the same geoip.dat (BLACKLIST-RU, TELEGRAM, GOOGLE, CLOUDFLARE, FACEBOOK,
    TWITTER, NETFLIX, FASTLY, CLOUDFRONT, TOR, CN, IR, PRIVATE, ...);
  - special-purpose IPv4 space (RFC 6890: private, CGNAT, loopback, link-local, multicast, ...);
  - every prefix announced by an AS of --asn (RIS whois dump from
    https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz): foreign clouds and hosters that are
    curtained or throttled from Russia.
Forbidden addresses inside geoip:ru itself stay direct, as in the plain list. So: every Russian
address stays direct, and the non-RU addresses that now go direct are in none of those sets.

check asserts exactly that for a given list: every geoip:ru prefix (and every prefix of each --old
list) is covered, no forbidden address outside geoip:ru is covered, at most --count routes. Exit 1
on failure. Deterministic: the same inputs give the same file.
"""
import argparse, gzip, hashlib, ipaddress, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from geoip_ru import fields  # noqa: E402
from ru_tradeoff import intervals, inter, load, merge_snapshots, minus  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))

# RFC 6890 special-purpose IPv4 (plus 0/8 and 240/4): never part of a supernet.
SPECIAL = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
           "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
           "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3"]


def geoip_lists(path):
    """{code: [(addr, plen)]} of every IPv4 list in geoip.dat."""
    res = {}
    for f, _, entry in fields(open(path, "rb").read()):
        if f != 1:
            continue
        code, nets = None, []
        for g, _, v in fields(entry):
            if g == 1:
                code = v.decode().upper()
            elif g == 2:
                ip, prefix = b"", 0
                for h, _, w in fields(v):
                    if h == 1:
                        ip = w
                    elif h == 2:
                        prefix = w
                if len(ip) == 4:
                    n = ipaddress.IPv4Network((ip, prefix), strict=False)
                    nets.append((int(n.network_address), n.prefixlen))
        if code and nets:
            res[code] = nets
    return res


def load_asns(path):
    out = set()
    for l in open(path):
        l = l.split("#", 1)[0].strip()
        if l:
            out.add(l.upper().removeprefix("AS"))
    return out


def ris_prefixes(path, asns):
    """Prefixes the given ASes originate (any origin of an AS set counts)."""
    out, when = [], "?"
    op = gzip.open if path.endswith(".gz") else open
    for l in op(path, "rt", errors="replace"):
        if l.startswith("%") or not l.strip():
            if "generated at" in l:
                when = l.split("generated at", 1)[1].strip().rstrip(".")
            continue
        p = l.split()
        if len(p) < 2:
            continue
        origins = p[0].strip("{}").split(",")
        if not any(o in asns for o in origins):
            continue
        try:
            n = ipaddress.IPv4Network(p[1])
        except ValueError:
            continue
        out.append((int(n.network_address), n.prefixlen))
    return out, when


def sources(geoip, ris, asn_file):
    """(RU prefixes, forbidden intervals outside RU, description of the inputs)."""
    L = geoip_lists(geoip)
    if "RU" not in L:
        sys.exit(f"no RU list in {geoip}")
    ru = sorted(set(intervals_to_prefixes(intervals(L["RU"]))))
    R = intervals(ru)
    forb = [x for k, v in L.items() if k not in ("RU", "IN-RU") for x in v]
    forb += [(int(n.network_address), n.prefixlen) for n in map(ipaddress.IPv4Network, SPECIAL)]
    asns = load_asns(asn_file)
    by_asn, when = ris_prefixes(ris, asns)
    forb += by_asn
    FX = minus(intervals(forb), R)
    sha = hashlib.sha256(open(geoip, "rb").read()).hexdigest()
    info = {"geoip_sha256": sha, "lists": len(L) - 1, "asns": len(asns), "asn_prefixes": len(by_asn), "ris": when}
    return ru, R, FX, info


def intervals_to_prefixes(iv):
    out = []
    for s, e in zip(*iv):
        for n in ipaddress.summarize_address_range(ipaddress.IPv4Address(s), ipaddress.IPv4Address(e - 1)):
            out.append((int(n.network_address), n.prefixlen))
    return out


def total(iv):
    return sum(e - s for s, e in zip(*iv))


def build(a):
    ru, R, FX, info = sources(a.geoip, a.ris, a.asn)
    lst = merge_snapshots(ru, [a.count], (FX[0], FX[1]))[a.count]
    if len(lst) > a.count:
        sys.exit(f"cannot reach {a.count} routes without covering a forbidden address (floor {len(lst)})")
    D = intervals(lst)
    extra = total(minus(D, R))
    print(f"RU {len(ru)} prefixes, {total(R)} addresses -> {len(lst)} routes, {extra} non-RU addresses direct", file=sys.stderr)
    print(f"# «Российские сайты напрямую»: generated by tools/ru_list.py build (do not edit by hand).")
    print(f"# geoip:ru of geoip.dat sha256 {info['geoip_sha256']}: {len(ru)} prefixes, {total(R)} addresses,")
    print(f"# merged into {len(lst)} routes; {extra} non-RU addresses go direct, none of them in another list")
    print(f"# of that geoip.dat, special-purpose space or {os.path.basename(a.asn)} ({info['asns']} ASes,")
    print(f"# {info['asn_prefixes']} prefixes in the RIS dump of {info['ris']}).")
    for x, l in lst:
        print(f"{ipaddress.IPv4Address(x)}/{l}")


def check(a):
    ru, R, FX, info = sources(a.geoip, a.ris, a.asn)
    lst = load(a.list)
    D = intervals(lst)
    ok = True

    def fail(msg):
        nonlocal ok
        ok = False
        print("FAIL", msg)

    if len(lst) > a.count:
        fail(f"{len(lst)} routes > {a.count}")
    for name, src in [("geoip:ru", ru)] + [(p, load(p)) for p in a.old or []]:
        S = intervals(src)
        miss = total(S) - inter(S, D)
        if miss:
            fail(f"{miss} addresses of {name} not covered")
        else:
            print(f"ok   all {len(src)} prefixes ({total(S)} addresses) of {name} covered")
    bad = inter(minus(D, R), FX)
    if bad:
        fail(f"{bad} forbidden addresses covered")
    else:
        print(f"ok   no forbidden address covered ({total(FX)} forbidden addresses outside geoip:ru)")
    print(f"{'ok  ' if len(lst) <= a.count else 'FAIL'} {len(lst)} routes (<= {a.count}); {total(minus(D, R))} non-RU addresses direct")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("build", "check"):
        p = sub.add_parser(c)
        p.add_argument("geoip")
        p.add_argument("ris")
        if c == "check":
            p.add_argument("list")
            p.add_argument("--old", action="append", help="an older list whose every prefix must be covered")
        p.add_argument("--count", type=int, default=10000)
        p.add_argument("--asn", default=os.path.join(HERE, "ru_list_asn.txt"))
    a = ap.parse_args()
    build(a) if a.cmd == "build" else check(a)


if __name__ == "__main__":
    main()
