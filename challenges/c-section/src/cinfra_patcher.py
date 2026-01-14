#!/usr/bin/env python3
import base64
import os
import subprocess
import sys
import tempfile


SECTION_FILE = ".cinfra.file"
SECTION_CONTENTS = ".cinfra.contents"


def run(cmd: list[str]) -> None:
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        raise RuntimeError(f"missing dependency: {cmd[0]} (install binutils)")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"command failed: {' '.join(cmd)} (exit={e.returncode})")


def read_line(prompt: str) -> str:
    sys.stdout.write(prompt)
    sys.stdout.flush()
    s = sys.stdin.readline()
    if s == "":
        raise EOFError
    return s.rstrip("\r\n")


def read_base64_blob() -> bytes:
    print("Send base64(ELF) lines, then a line containing: END", flush=True)
    chunks: list[str] = []
    while True:
        line = sys.stdin.readline()
        if line == "":
            raise EOFError
        line = line.strip()
        if line == "END":
            break
        if line:
            chunks.append(line)
        if sum(len(c) for c in chunks) > 4_000_000:
            raise RuntimeError("input too large")
    data = "".join(chunks)
    try:
        blob = base64.b64decode(data, validate=True)
    except Exception as e:
        raise RuntimeError(f"invalid base64: {e}") from e
    if len(blob) > 2_000_000:
        raise RuntimeError("ELF too large")
    return blob


def write_base64_blob(blob: bytes) -> None:
    b64 = base64.b64encode(blob).decode()
    print("BEGIN", flush=True)
    for i in range(0, len(b64), 76):
        print(b64[i : i + 76], flush=True)
    print("END", flush=True)


def patch_elf_interactive() -> None:
    filename = read_line("filename> ")
    contents = read_line("contents> ")

    try:
        elf = read_base64_blob()
    except Exception:
        print("Wrong format", flush=True)
        return

    try:
        with tempfile.TemporaryDirectory() as td:
            in_elf = os.path.join(td, "in.elf")
            out_elf = os.path.join(td, "out.elf")
            sec_file = os.path.join(td, "cinfra_file.bin")
            sec_contents = os.path.join(td, "cinfra_contents.bin")

            with open(in_elf, "wb") as f:
                f.write(elf)

            with open(sec_file, "wb") as f:
                f.write(filename.encode() + b"\x00")
            with open(sec_contents, "wb") as f:
                f.write(contents.encode() + b"\x00")

            run(
                [
                    "objcopy",
                    "--add-section",
                    f"{SECTION_FILE}={sec_file}",
                    "--set-section-flags",
                    f"{SECTION_FILE}=contents,readonly",
                    "--add-section",
                    f"{SECTION_CONTENTS}={sec_contents}",
                    "--set-section-flags",
                    f"{SECTION_CONTENTS}=contents,readonly",
                    in_elf,
                    out_elf,
                ]
            )

            patched = open(out_elf, "rb").read()
    except Exception:
        print("Wrong format", flush=True)
        return

    print("Here is your patched ELF as base64:", flush=True)
    write_base64_blob(patched)
    print("Reminder: it will run on the c-infrastructure only if:", flush=True)
    print(f"- host has file {filename!r}", flush=True)
    print(f"- its contents equal {contents!r} (exact)", flush=True)


def run_sample() -> None:
    sample = "/home/challenge/ro/sample"
    if not os.path.exists(sample):
        raise RuntimeError("sample not available on this host")
    os.execv(sample, [sample])


def main() -> int:
    print("Welcome to the c-infrastructure patcher", flush=True)
    print(
        f"""
This service make your ELF compatible with the c-infrastructure.
In the c-infrastructure, binaries are marked with the contents of a file. 
The marked binary will run on a host only if the file exists on that host and its contents match the marked contents.
This approach allows for fine-grained control over what can be executed on the host.""",
        flush=True,
    )
    print("1) patch an ELF", flush=True)
    print("2) run a c-executable sample on this host(/proc reader)", flush=True)
    print("3) exit", flush=True)

    while True:
        try:
            choice = read_line("> ").strip()
        except EOFError:
            return 0

        if choice == "1":
            patch_elf_interactive()
            return 0
        if choice == "2":
            run_sample()
            return 0
        if choice == "3":
            print("bye", flush=True)
            return 0
        print("invalid choice", flush=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(1)
