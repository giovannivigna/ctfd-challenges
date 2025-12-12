import subprocess
import argparse
import os

FLAG_PATH = "/flag"
WRITE_DIR = "../rw/"
def get_flag():
    try:
        with open(FLAG_PATH, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "ictf{placeholder_flag_file_missing}"

def run_codeql_query(query, codeql_db_path):
    os.chdir(WRITE_DIR)
    
    query_file = "query.ql"

    with open(query_file, "w") as f:
        f.write(query)

    result_file = "result.bqrs"
    
    subprocess.run([
        "codeql", "query", "run", query_file,
        "--database", codeql_db_path,
        "--output", result_file
    ], check=True)

    # Decode the result to CSV so we can check it
    output = subprocess.check_output([
        "codeql", "bqrs", "decode", "--format=csv", result_file
    ])

    return output.decode()

def read_c_file(c_file_path):
    with open(c_file_path, 'r') as f:
        return f.read()

def get_query():
    query_lines = []
    while True:
        line = input()
        if line.strip() == "DONE":
            break
        query_lines.append(line)

    query = "\n".join(query_lines)
    return query

def get_problem():
    return """Write a CodeQL query that will find the name of a function that is never called.
Please consider that a query usually start with 'import cpp' and has a 'from', 'where', and 'select' clause."""

def verify_result(query, result):
    print("Received query:")
    print("=" * 40)
    print(query)
    print("=" * 40)

    print("Produced result:")
    print("=" * 40)
    print(result)
    print("=" * 40)

    if "targetFunction" in result:
        print("Incorrect: Found function that is actually called")
        return False

    if "from" not in query.lower():
        print("Incorrect: Query does not contain 'from'")
        return False
    
    if "where" not in query.lower():
        print("Incorrect: Query does not contain 'where'")
        return False

    if "select" not in query.lower():
        print("Incorrect: Query does not contain 'select'")
        return False

    if "anotherFunction" in result:
        return True
    
def main():
    parser = argparse.ArgumentParser(description="CodeQL CTF Challenge Server")
    parser.add_argument("c_file", help="Path to the C source file")
    parser.add_argument("codeql_db", help="Path to the pre-built CodeQL database")
    
    args = parser.parse_args()

    c_program = read_c_file(args.c_file)

    print(f"My user ID is: {os.getuid()}")
    print(f"My environment is:")
    for key, value in os.environ.items():
        print(f'{key}={value}')
    
    # Makes sure that the home dir is /home/challenge
    os.environ['HOME'] = '/home/challenge'
    os.environ['USER'] = 'challenge'
    
    print("Welcome to codequill!")
    print("Your target program is:")
    print("=" * 40)
    print(c_program)
    print("=" * 40)
    print("")
    print(get_problem())
    print("\nSubmit your query (end with a line containing only 'DONE'):")

    query = get_query()
    
    try:
        result = run_codeql_query(query, args.codeql_db)

        if verify_result(query, result):
            flag = get_flag()
            print(f"Congratulations! Here is your flag: {flag}")
        else:
            print("Incorrect result. Try again!")
    except subprocess.CalledProcessError as e:
        print(f"CodeQL error: {e}")

if __name__ == "__main__":
    main()