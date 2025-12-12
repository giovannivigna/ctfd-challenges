#!/usr/bin/env python3  
import sys
import secrets
import string

random1 = bytes(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16)).encode())
random2 = bytes(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24)).encode())
random3 = bytes(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8)).encode())

def print_crashing_input():

    CRASHING_INPUT = b"A" * 256

    magic = b"\xde\xad\xbe\xef"
    protocol_major = b"\x04"
    protocol_minor = b"\x01"
    payload_length = b"\x00\x01"

    section1_length = b"\x07\x00"
    section1_type = b"\x01"
    section1_data = b"AUTHKEY"

    section2_length = b"\x0c\x00"
    section2_type = b"\x02"
    section2_data = b"SECRET_CRASH"


    payload = magic + protocol_major + protocol_minor + payload_length + \
                    section1_length + section1_type + section1_data + \
                    section2_length + section2_type + section2_data + CRASHING_INPUT
    sys.stdout.buffer.write(payload)

def print_almost_crashing_input():

    CRASHING_INPUT = b"A" * 256

    magic = b"\xde\xad\xbe\xef"
    protocol_major = b"\x04"
    protocol_minor = b"\x01"
    payload_length = b"\x00\x01"

    section1_length = b"\x07\x00"
    section1_type = b"\x01"
    section1_data = b"AUTHKEY"

    section2_length = b"\x0c\x00"
    section2_type = b"\x02"
    section2_data = b"SECRET_CRASt"


    payload = magic + protocol_major + protocol_minor + payload_length + \
                    section1_length + section1_type + section1_data + \
                    section2_length + section2_type + section2_data + CRASHING_INPUT
    sys.stdout.buffer.write(payload)

def print_seed():
    magic = b"\xde\xad\xbe\xef"
    protocol_major = b"\x04"
    protocol_minor = b"\x01"
    payload_length = b"\x00\x01"

    section1_data = b"AUTHKEY"
    section2_data = b"SECRET_CRASH"
    section3_data = b"A" * 256

    payload = magic + protocol_major + protocol_minor + payload_length + \
                    random1 + section1_data + random2 + section2_data + random3 + section3_data
    sys.stdout.buffer.write(payload)

if sys.argv[1] == "crash":
    print_crashing_input()
elif sys.argv[1] == "crashy":
    print_almost_crashing_input()
elif sys.argv[1] == "seed":
    print_seed()
else:
    print("Usage: python3 exploit.py [crash|crashy|seed]")
