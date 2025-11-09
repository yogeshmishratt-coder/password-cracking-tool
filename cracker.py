import argparse
import hashlib
import itertools
import string
import sys
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

def generate_passwords(chars, min_len, max_len):
    """
    Generator for brute-force password combinations using itertools.product
    """
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(chars, repeat=length):
            yield "".join(combo)

def check_hash(password, target_hash, hash_fn, found_event):
    """
    Hashes a single password and compares it to the target hash.
    
    If a password is found, it sets the 'found_event' to signal
    other threads to stop.
    """
    # Stop checking if another thread already found the password
    if found_event.is_set():
        return None
    
    # Compute the hash of the current password candidate
    hashed = hash_fn(password.encode()).hexdigest()
    
    if hashed == target_hash:
        found_event.set()  # Signal that we found the password
        return password  # Return the found password
    
    return None

def crack_hash(target_hash, hash_type, workers, wordlist=None, min_len=1, max_len=4, chars=None):
    """
    Main cracking function. Manages ThreadPoolExecutor and tqdm.
    """
    
    # 1. Validate and get the hash function from hashlib
    if not hasattr(hashlib, hash_type):
        print(f"[!] Error: Hash type '{hash_type}' not supported by hashlib.", file=sys.stderr)
        return None
    hash_fn = getattr(hashlib, hash_type)

    # This event is used to signal all threads to stop once a match is found
    found_event = threading.Event()
    found_password = None

    # 2. Setup the ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {}
        
        if wordlist:
            # --- WORDLIST MODE ---
            if not os.path.isfile(wordlist):
                print(f"[!] Error: Wordlist file not found: {wordlist}", file=sys.stderr)
                return None
            
            # Read all passwords into memory
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
                passwords = [line.strip() for line in f.readlines()]
            
            total = len(passwords)
            desc = "Cracking (Wordlist)"
            
            # Submit all wordlist tasks
            for p in passwords:
                futures[executor.submit(check_hash, p, target_hash, hash_fn, found_event)] = p

        else:
            # --- BRUTE-FORCE MODE ---
            print(f"[*] Starting brute-force: min={min_len}, max={max_len}, chars='{chars[:15]}...'")
            
            # Calculate total number of passwords for the progress bar
            total = 0
            char_count = len(chars)
            for i in range(min_len, max_len + 1):
                total += char_count ** i
            
            desc = "Cracking (Brute-Force)"
            
            # Create the password generator
            password_gen = generate_passwords(chars, min_len, max_len)
            
            # Submit all generated password tasks.
            for p in password_gen:
                futures[executor.submit(check_hash, p, target_hash, hash_fn, found_event)] = p

        # 3. Process results as they complete, with a progress bar
        print(f"[*] Submitting {total:,} password candidates to {workers} workers...")
        try:
            pbar = tqdm(total=total, desc=desc)
            for future in as_completed(futures):
                pbar.update(1)  # Update progress bar for each completed task
                result = future.result()
                
                if result:
                    found_password = result
                    found_event.set()  # Tell all other threads to stop
                    
                    # Cancel all pending futures to stop work immediately
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    break
        except KeyboardInterrupt:
            print("\n[!] Cracking interrupted by user.")
            found_event.set()
            for f in futures: f.cancel()
        finally:
            pbar.close()

    return found_password

# 4. Main execution block
if __name__ == "__main__":
    # 5. Setup command-line argument parsing
    parser = argparse.ArgumentParser(
        description="Password Cracker Project",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Required argument
    parser.add_argument("hash", help="The target hash to crack.")
    
    # Mode selection (Wordlist or Brute-Force)
    # The user MUST choose one
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-w", "--wordlist", help="Path to the password wordlist.")
    mode_group.add_argument("-b", "--brute", action="store_true", help="Use brute-force generation mode.")

    # Hash options
    parser.add_argument("-t", "--type", default="md5", help="Hash type (e.g., md5, sha1, sha256). Default: md5")
    
    # Brute-force specific options
    brute_group = parser.add_argument_group('brute-force options')
    brute_group.add_argument("-min", "--min_length", type=int, default=1, help="Minimum password length (default: 1)")
    brute_group.add_argument("-max", "--max_length", type=int, default=4, help="Maximum password length (default: 4)")
    
    # Define default character set using string module
    default_chars = string.ascii_letters + string.digits
    brute_group.add_argument("-c", "--chars", default=default_chars, help="Character set for brute-force (default: a-zA-Z0-9)")

    # Performance options
    parser.add_argument("-wo", "--workers", type=int, default=10, help="Number of concurrent threads (default: 10)")
    
    args = parser.parse_args()
    
    if args.brute:
        # --- Run Brute-Force Mode ---
        password = crack_hash(
            target_hash=args.hash,
            hash_type=args.type,
            workers=args.workers,
            min_len=args.min_length,
            max_len=args.max_length,
            chars=args.chars
        )
    else:
        # --- Run Wordlist Mode ---
        password = crack_hash(
            target_hash=args.hash,
            hash_type=args.type,
            workers=args.workers,
            wordlist=args.wordlist
        )

    # 6. Print final result
    if password:
        print(f"\n[+] SUCCESS! Password found: {password}")
    else:
        print(f"\n[-] FAILED. Password not found.")
