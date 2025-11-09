================================
Password Cracker Script (cracker.py)
================================

This Python script cracks password hashes using two different methods:
1.  **Wordlist Attack:** Checks passwords from a specified file.
2.  **Brute-Force Attack:** Tries every possible combination of characters.

The script is multithreaded to run faster and uses `tqdm` to show a progress bar.


------------------------
Prerequisites
------------------------

Before running, you must install one external library, `tqdm`.

1.  Open your command prompt (cmd).
2.  Run the following command:
    pip install tqdm


------------------------
How to Run
------------------------

You MUST run this script from your command prompt (cmd, PowerShell, Terminal), not by pressing "Run" in a code editor.

The basic command structure is:
python cracker.py [HASH] [MODE] [OPTIONS]


------------------------
Arguments & Options
------------------------

[HASH]
    (Required) The password hash you want to crack.

[MODE] (Choose one)
    -w, --wordlist FILE
        Use wordlist attack mode. 'FILE' is the path to your wordlist (e.g., wordlist.txt).
    
    -b, --brute
        Use brute-force attack mode.

[OPTIONS]
    -t, --type TYPE
        The hash algorithm used (e.g., md5, sha1, sha256, sha512).
        (Default: md5)

    -wo, --workers NUM
        The number of concurrent threads to use for cracking.
        (Default: 10)

[BRUTE-FORCE OPTIONS] (Only work with -b)
    -min, --min_length NUM
        The minimum password length to check.
        (Default: 1)

    -max, --max_length NUM
        The maximum password length to check.
        (Default: 4)

    -c, --chars CHARS
        The character set to use for brute-force.
        (Default: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


------------------------
Examples
------------------------

Let's use the MD5 hash for "test": 098f6bcd4621d373cade4e832627b4f6

---
Example 1: Wordlist Attack
(Assumes you have a file named `wordlist.txt` in the same folder)

    python cracker.py 098f6bcd4621d373cade4e832627b4f6 -w wordlist.txt

---
Example 2: Brute-Force Attack (to find "test")
(Searches for 4-character, lowercase-only passwords)

    python cracker.py 098f6bcd4621d373cade4e832627b4f6 -b --min_length 4 --max_length 4 -c "abcdefghijklmnopqrstuvwxyz"

---
Example 3: Brute-Force Attack (Default)
(Searches for 1-4 character passwords using letters and numbers)

    python cracker.py 098f6bcd4621d373cade4e832627b4f6 -b --min_length 1 --max_length 4

---
Example 4: SHA256 Hash with Wordlist
(Uses 20 threads to check a SHA256 hash)
(Hash for "password" is 5e884898da28047151d0e56f8dc6292773603d0d6aabb82fbb5b9f74d4624d62)

    python cracker.py 5e884898da28047151d0e56f8dc6292773603d0d6aabb82fbb5b9f74d4624d62 -w wordlist.txt -t sha256 -wo 20
