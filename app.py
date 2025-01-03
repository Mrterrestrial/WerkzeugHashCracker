import argparse
from werkzeug.security import check_password_hash
from multiprocessing import Pool, cpu_count, Manager
from tqdm import tqdm  # Import tqdm for progress bars

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

def perform_attack(hashed_password, wordlist_path, chunk_size):
    """Performs dictionary attack using multiprocessing on hashed password."""
    hashed_password = hashed_password.strip()
    print("Proceeding with dictionary attack...")

    with Manager() as manager:
        found_flag = manager.Value('b', False)
        with Pool(cpu_count()) as pool:
            wordlist_chunks = load_wordlist(wordlist_path, chunk_size=chunk_size)
            total_chunks = sum(1 for _ in wordlist_chunks)  # Count total chunks
            wordlist_chunks = load_wordlist(wordlist_path, chunk_size=chunk_size)  # Re-load the wordlist for processing
            chunk_counter = 0

            # Use tqdm to show progress for each chunk
            for chunk in tqdm(wordlist_chunks, desc="Processing chunks", total=total_chunks):
                if found_flag.value:
                    break
                results = pool.starmap_async(check_password_chunk, [(chunk, hashed_password, found_flag)])
                found_passwords = list(filter(None, results.get()))
                if found_passwords:
                    print("Password found:", found_passwords[0])
                    return found_passwords[0]
                chunk_counter += 1

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
        help="Path to the wordlist file (default: 'Wordlist/small_rockyou.txt')."
    )
    parser.add_argument(
        "-c", "--chunk_size",
        type=int,
        default=1000,
        help="Chunk size for password checking (default: 1000)."
    )

    args = parser.parse_args()
    perform_attack(args.hashed_password, args.wordlist, args.chunk_size)

if __name__ == "__main__":
    main()

