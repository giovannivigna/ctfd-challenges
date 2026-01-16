#!/usr/bin/env python3
import argparse
import sys


KEY = bytes([0xC3, 0x7A, 0x15, 0xE9, 0x4B, 0x2D, 0x90, 0xFE])


def rol8(x: int, r: int) -> int:
    r &= 7
    return ((x << r) & 0xFF) | (x >> (8 - r))


def obfuscate_flag(flag_ascii: str) -> bytes:
    try:
        flag_bytes = flag_ascii.encode("ascii")
    except UnicodeEncodeError as e:
        raise SystemExit(f"flag must be ASCII: {e}") from e

    if len(flag_bytes) >= 40:
        raise SystemExit("flag must be < 40 bytes")

    plain = flag_bytes + b"\x00" * (40 - len(flag_bytes))

    out = bytearray(40)
    for i in range(40):
        x = plain[i]
        x ^= KEY[i % len(KEY)]
        x ^= (0xA5 + (i * 7)) & 0xFF
        x = rol8(x, (i % 7) + 1)
        x ^= (0x3C ^ ((i * 11) & 0xFF)) & 0xFF
        out[i] = x
    return bytes(out)


def to_c_initializer(b: bytes) -> str:
    return ", ".join(f"0x{v:02x}" for v in b)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate 40-byte comparison value for extrafirm")
    ap.add_argument("flag", help="ASCII flag (<40 bytes), e.g. ictf{...}")
    args = ap.parse_args()

    val = obfuscate_flag(args.flag)

    sys.stdout.write("hex: " + val.hex() + "\n")
    sys.stdout.write("c:   " + to_c_initializer(val) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
