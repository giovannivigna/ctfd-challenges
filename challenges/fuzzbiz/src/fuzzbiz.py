import sys
import subprocess
import os


def main():
    if (len(sys.argv) < 3):
        print("Usage: python3 fuzzbiz.py <vulnerable_program>.c <vulnerable_program>")
        sys.exit(1)
    
    print("Hello! Welcome to the FuzzBiz challenge.")
    print("Please provide the number of bytes to read, followed by the payload.")
    print("I will pass whatever you provide to the following program:")
    try:
        with open(sys.argv[1], "r") as program_file:
                    print(program_file.read())
    except Exception as e:
        print(f"Error reading program file [{sys.argv[1]}]: {e}")
        sys.exit(1)
        
    try:
        print("Enter your payload length:", flush=True)

        # Read the number of bytes to consume
        num_bytes = int(sys.stdin.readline().strip())
        
        print("Enter your payload:", flush=True)
        # Read exactly num_bytes from stdin
        payload = sys.stdin.buffer.read(num_bytes)

        process = subprocess.Popen(
            [sys.argv[2]],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        stdout, stderr = process.communicate(input=payload)

        if stdout:
            sys.stdout.write(stdout.decode(errors="ignore"))
        if stderr:
            sys.stderr.write(stderr.decode(errors="ignore"))

        # Check if the process crashed (non-zero exit or segmentation fault)
        if process.returncode not in (0, 1):  # Crashes typically have return codes > 1
            print("💥 Program crashed! Fetching the flag... 💥")
            try:
                with open("/flag", "r") as flag_file:
                    print(flag_file.read().strip())
            except Exception as e:
                print(f"Error reading flag: {e}")

    except ValueError:
        print("Invalid input: Expected a number first.")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()