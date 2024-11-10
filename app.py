"""
Dictionary attack on Werkzeug hashed password to find plaintext.
Uses multiprocessing to speed up brute-forcing by checking chunks in parallel.
"""

import argparse
from werkzeug.security import check_password_hash
from multiprocessing import Pool, cpu_count, Manager

def load_wordlist(wordlist_path, chunk_size=1000):
    """Yields chunks of passwords from the wordlist file to limit memory usage."""
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as file:
            chunk = []
            for line in file:
                chunk.append(line.strip())
                if len(chunk) >= chunk_size:
                    yield chunk
                    chunk = []
            if chunk:
                yield chunk
    except FileNotFoundError:
        print(f"Error: File '{wordlist_path}' not found.")
        return

def check_password_chunk(chunk, hashed_password, found_flag):
    """Checks a chunk of passwords against the hashed password."""
    for word in chunk:
        if found_flag.value:
            return None
        if check_password_hash(hashed_password, word):
            found_flag.value = True
            return word
    return None

def perform_attack(hashed_password, wordlist_path):
    """Performs dictionary attack using multiprocessing on hashed password."""
    hashed_password = hashed_password.strip()
    print("Proceeding with dictionary attack...")

    with Manager() as manager:
        found_flag = manager.Value('b', False)
        with Pool(cpu_count()) as pool:
            for chunk in load_wordlist(wordlist_path):
                if found_flag.value:
                    break
                results = pool.starmap_async(check_password_chunk, [(chunk, hashed_password, found_flag)])
                found_passwords = list(filter(None, results.get()))
                if found_passwords:
                    print("Password found:", found_passwords[0])
                    return found_passwords[0]

    print("Password not found in wordlist.")
    return None

def main():
    parser = argparse.ArgumentParser(
        description="Dictionary attack tool to find the plaintext password for a Werkzeug hashed password."
    )
    parser.add_argument(
        "hashed_password",
        help="The hashed password to crack."
    )
    parser.add_argument(
        "-w", "--wordlist",
        default="Wordlist/small_rockyou.txt",
        help="Path to the wordlist file (default: 'Wordlist/rockyou.txt')."
    )

    args = parser.parse_args()
    perform_attack(args.hashed_password, args.wordlist)

if __name__ == "__main__":
    main()
