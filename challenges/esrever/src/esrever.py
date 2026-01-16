#!/usr/bin/env python3
"""
esrever: A reversing challenge that asks about binary structure
"""

import sys
import os
import tempfile
import subprocess
import random
import string
import struct
import signal
import argparse
import hashlib

DURATION = 10

def handler(signum, frame):
    print("Timeout!")
    sys.exit(1)

def generate_secret():
    """Generate a random secret password"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

def extract_binary_info(binary_path):
    """Extract information from the compiled binary"""
    try:
        from elftools.elf.elffile import ELFFile  # pyright: ignore[reportMissingImports]
        from elftools.elf.sections import SymbolTableSection  # pyright: ignore[reportMissingImports]
    except ImportError as e:
        raise RuntimeError("pyelftools not installed (required for interactive mode)") from e

    with open(binary_path, 'rb') as f:
        elf = ELFFile(f)
        
        # Find text segment address
        text_segment = None
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_LOAD' and segment['p_flags'] & 0x1:  # Executable
                text_segment = segment
                break
        
        text_addr = text_segment['p_vaddr'] if text_segment else None
        
        # Find initialized data segment size
        data_size = 0
        for section in elf.iter_sections():
            if section['sh_type'] == 'SHT_PROGBITS' and section['sh_flags'] & 0x2:  # Writeable
                data_size += section['sh_size']
        
        # Find main function address
        main_addr = None
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if symbol.name == 'main':
                        main_addr = symbol['st_value']
                        break
                if main_addr:
                    break
        
        return text_addr, data_size, main_addr

def _default_template_path():
    # Prefer the template next to this script (local dev / repository layout),
    # but keep the original container path as a fallback.
    local = os.path.join(os.path.dirname(__file__), 'esrever.c')
    if os.path.exists(local):
        return local
    return '/home/challenge/src/esrever.c'

def _derive_text_base(secret: str, padding_size: int) -> int:
    """
    Derive a page-aligned text segment base address from (secret, padding_size).
    This makes the text segment virtual address change on every compile (since
    secret/padding_size are re-randomized each connection).
    """
    # Keep in a conservative range that works for non-PIE executables.
    base_min = 0x400000
    base_span = 0x1000000  # 16 MiB span
    page = 0x1000

    h = hashlib.sha256(f"{secret}:{padding_size}".encode()).digest()
    n_pages = base_span // page
    page_idx = int.from_bytes(h[:4], "little") % n_pages
    return base_min + page_idx * page


def compile_binary(secret, padding_size, out_dir, *, template_path=None, c_filename='esrever.c', binary_filename='esrever', text_base=None):
    """Generate a C file from the template and compile it, returning (c_path, binary_path)."""
    os.makedirs(out_dir, exist_ok=True)
    c_file = os.path.join(out_dir, c_filename)
    binary_file = os.path.join(out_dir, binary_filename)
    
    # Read the template
    template_path = template_path or _default_template_path()
    with open(template_path, 'r') as f:
        template = f.read()
    
    # Replace placeholders
    code = template.replace('__SECRET__', secret)
    code = code.replace('__PADDING_SIZE__', str(padding_size))
    
    # Write the modified C file
    with open(c_file, 'w') as f:
        f.write(code)
    
    # Compile
    if text_base is None:
        text_base = _derive_text_base(secret, padding_size)
    # Force a different text segment virtual address per compilation.
    # (This affects the ELF program header p_vaddr for the executable PT_LOAD.)
    compile_cmd = [
        'gcc',
        '-no-pie',
        '-fno-pic',
        f'-Wl,-Ttext-segment=0x{text_base:x}',
        '-o',
        binary_file,
        c_file,
    ]
    result = subprocess.run(compile_cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Compilation error: {result.stderr}")
        return None, None
    
    return c_file, binary_file

def parse_args(argv):
    p = argparse.ArgumentParser(description="esrever challenge runner / build helper")
    p.add_argument(
        "--build-only",
        action="store_true",
        help="Only generate the C file from the template and compile it, then exit.",
    )
    p.add_argument(
        "--out-dir",
        default=None,
        help="Output directory for --build-only (default: current directory).",
    )
    p.add_argument(
        "--secret",
        default=None,
        help="Override the randomly generated secret (default: random).",
    )
    p.add_argument(
        "--padding-size",
        type=int,
        default=None,
        help="Override the random padding size (default: random).",
    )
    return p.parse_args(argv)

def main():
    args = parse_args(sys.argv[1:])
    
    # Generate random values
    secret = args.secret if args.secret is not None else generate_secret()
    padding_size = args.padding_size if args.padding_size is not None else random.randint(100, 1000)  # Random padding to vary segment sizes

    if args.build_only:
        out_dir = args.out_dir or os.getcwd()
        c_path, binary_path = compile_binary(
            secret,
            padding_size,
            out_dir,
            c_filename="esrever.gen.c",
            binary_filename="esrever.gen",
        )
        if not binary_path:
            print("Failed to compile binary")
            return 1
        print(f"Generated: {c_path}")
        print(f"Compiled:  {binary_path}")
        return 0

    signal.alarm(DURATION)
    signal.signal(signal.SIGALRM, handler)
    
    # Create temporary directory
    temp_dir = tempfile.mkdtemp(dir='/home/challenge/rw')
    
    try:
        # Compile the binary
        _, binary_file = compile_binary(secret, padding_size, temp_dir)
        if not binary_file:
            print("Failed to compile binary")
            return 1
        
        # Extract binary information
        try:
            text_addr, data_size, main_addr = extract_binary_info(binary_file)
        except RuntimeError as e:
            print(f"Error: {e}")
            return 1
        
        # Read binary and send it
        with open(binary_file, 'rb') as f:
            binary_data = f.read()
        
        binary_len = len(binary_data)
        
        # Send binary length and binary
        print(f"Binary length: {binary_len}")
        sys.stdout.flush()
        sys.stdout.buffer.write(binary_data)
        sys.stdout.buffer.flush()
        
        # Ask questions
        print("\nQuestion 1: What is the address of the text segment? (hex, e.g., 0x400000)")
        sys.stdout.flush()
        answer1 = input().strip()
        
        try:
            if answer1.startswith('0x') or answer1.startswith('0X'):
                user_text_addr = int(answer1, 16)
            else:
                user_text_addr = int(answer1, 16)
        except ValueError:
            print("Invalid format!")
            return 1
        
        if user_text_addr != text_addr:
            print(f"Incorrect! Expected: 0x{text_addr:x}")
            return 1
        
        print("Correct!")
        print("\nQuestion 2: What is the size of the initialized data segment? (decimal)")
        sys.stdout.flush()
        answer2 = input().strip()
        
        try:
            user_data_size = int(answer2)
        except ValueError:
            print("Invalid format!")
            return 1
        
        if user_data_size != data_size:
            print(f"Incorrect! Expected: {data_size}")
            return 1
        
        print("Correct!")
        print("\nQuestion 3: What is the secret password?")
        sys.stdout.flush()
        answer3 = input().strip()
        
        if answer3 != secret:
            print(f"Incorrect! Expected: {secret}")
            return 1
        
        print("Correct!")
        print("\nQuestion 4: What is the address of the 'main' function? (hex, e.g., 0x401000)")
        sys.stdout.flush()
        answer4 = input().strip()
        
        try:
            if answer4.startswith('0x') or answer4.startswith('0X'):
                user_main_addr = int(answer4, 16)
            else:
                user_main_addr = int(answer4, 16)
        except ValueError:
            print("Invalid format!")
            return 1
        
        if user_main_addr != main_addr:
            print(f"Incorrect! Expected: 0x{main_addr:x}")
            return 1
        
        print("Correct!")
        print("\nCongratulations! You've successfully reversed the binary!")
        with open('/flag', 'r') as f:
            print(f.read())
        
        return 0
        
    finally:
        # Cleanup
        import shutil
        try:
            shutil.rmtree(temp_dir)
        except:
            pass

if __name__ == '__main__':
    sys.exit(main())

