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

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    print("Error: pyelftools not installed")
    sys.exit(1)

DURATION = 30

def handler(signum, frame):
    print("Timeout!")
    sys.exit(1)

def generate_secret():
    """Generate a random secret password"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

def extract_binary_info(binary_path):
    """Extract information from the compiled binary"""
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

def compile_binary(secret, padding_size, temp_dir):
    """Compile esrever.c with the secret and padding"""
    c_file = os.path.join(temp_dir, 'esrever.c')
    binary_file = os.path.join(temp_dir, 'esrever')
    
    # Read the template
    template_path = '/home/challenge/src/esrever.c'
    with open(template_path, 'r') as f:
        template = f.read()
    
    # Replace placeholders
    code = template.replace('__SECRET__', secret)
    code = code.replace('__PADDING_SIZE__', str(padding_size))
    
    # Write the modified C file
    with open(c_file, 'w') as f:
        f.write(code)
    
    # Compile
    compile_cmd = ['gcc', '-no-pie', '-fno-pic', '-o', binary_file, c_file]
    result = subprocess.run(compile_cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Compilation error: {result.stderr}")
        return None
    
    return binary_file

def main():
    signal.alarm(DURATION)
    signal.signal(signal.SIGALRM, handler)
    
    # Generate random values
    secret = generate_secret()
    padding_size = random.randint(100, 1000)  # Random padding to vary segment sizes
    
    # Create temporary directory
    temp_dir = tempfile.mkdtemp(dir='/home/challenge/rw')
    
    try:
        # Compile the binary
        binary_file = compile_binary(secret, padding_size, temp_dir)
        if not binary_file:
            print("Failed to compile binary")
            return 1
        
        # Extract binary information
        text_addr, data_size, main_addr = extract_binary_info(binary_file)
        
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

