#!/usr/bin/env python3
"""IPv4 prefixes of one country from xray's geoip.dat, aggregated, one CIDR per line.

usage: geoip_ru.py <geoip.dat> [country=RU] > ru4.txt

geoip.dat is a protobuf GeoIPList: repeated GeoIP geoip = 1; GeoIP { string country_code = 1;
repeated CIDR cidr = 2; ... }; CIDR { bytes ip = 1; uint32 prefix = 2; }. No dependencies.
The counts before/after aggregation go to stderr. Used for ios/App/Resources/ru4.txt
(the "Российские сайты напрямую" excluded routes); see ios/README.md for the source file.
"""
import ipaddress
import sys


def varint(b, i):
    r = s = 0
    while True:
        c = b[i]
        i += 1
        r |= (c & 0x7F) << s
        if c < 0x80:
            return r, i
        s += 7


def fields(b):
    """(field number, wire type, value) of one message; value is bytes for length-delimited."""
    i = 0
    while i < len(b):
        key, i = varint(b, i)
        f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = varint(b, i)
        elif wt == 2:
            n, i = varint(b, i)
            v = b[i:i + n]
            i += n
        elif wt == 1:
            v = b[i:i + 8]
            i += 8
        elif wt == 5:
            v = b[i:i + 4]
            i += 4
        else:
            raise ValueError(f"wire type {wt}")
        yield f, wt, v


def main():
    path = sys.argv[1]
    want = (sys.argv[2] if len(sys.argv) > 2 else "RU").upper()
    data = open(path, "rb").read()
    nets = []
    found = False
    for f, _, entry in fields(data):
        if f != 1:
            continue
        code, cidrs = None, []
        for g, _, v in fields(entry):
            if g == 1:
                code = v.decode()
            elif g == 2:
                cidrs.append(v)
        if (code or "").upper() != want:
            continue
        found = True
        for c in cidrs:
            ip, prefix = b"", 0
            for h, _, v in fields(c):
                if h == 1:
                    ip = v
                elif h == 2:
                    prefix = v
            if len(ip) == 4:
                nets.append(ipaddress.IPv4Network((ip, prefix), strict=False))
    if not found:
        sys.exit(f"no country {want} in {path}")
    agg = list(ipaddress.collapse_addresses(nets))
    total = sum(n.num_addresses for n in agg)
    print(f"{want}: {len(nets)} IPv4 prefixes, {len(agg)} after aggregation, {total} addresses", file=sys.stderr)
    for n in agg:
        print(n)


if __name__ == "__main__":
    main()
