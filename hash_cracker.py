#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: Sher Khan
# LinkedIn: https://www.linkedin.com/in/sherkhan-sk
# Contact: +923122632023
#
# --- Simple Hash Identifier and Cracker (Colored Version) ---
#
# DISCLAIMER:
# This script is intended for educational purposes only.
# Misuse of this script for unauthorized activities is strictly prohibited.
# The author is not responsible for any illegal or unethical use of this tool.
# Always ensure you have explicit permission before attempting to crack any hashes.

import re
import hashlib
import itertools
import string
import time
import os

# --- ANSI Color Codes ---
class Colors:
    HEADER = '\033[95m'    # Light Magenta
    OKBLUE = '\033[94m'     # Light Blue
    OKCYAN = '\033[96m'     # Light Cyan
    OKGREEN = '\033[92m'    # Light Green
    WARNING = '\033[93m'    # Yellow
    FAIL = '\033[91m'       # Red
    ENDC = '\033[0m'        # Reset to default
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'         # Dim color

# Helper function for colored printing
def cprint(text, color=Colors.ENDC, bold=False, underline=False, dim=False, **kwargs):
    prefix = ""
    if bold:
        prefix += Colors.BOLD
    if underline:
        prefix += Colors.UNDERLINE
    if dim:
        prefix += Colors.DIM
    print(f"{prefix}{color}{text}{Colors.ENDC}", **kwargs)

# --- Part 1: Hash Identifier ---
def identify_hash(hash_string):
    """
    Identifies the type of a given hash string based on length and format.
    """
    hash_string = str(hash_string).strip()
    length = len(hash_string)
    identified_types = []

    # MD5: 32 hex characters
    if length == 32 and re.fullmatch(r"^[a-f0-9]{32}$", hash_string, re.IGNORECASE):
        identified_types.append("MD5")
        identified_types.append("NTLM (potentially, shares MD5 format)")
    if length == 40 and re.fullmatch(r"^[a-f0-9]{40}$", hash_string, re.IGNORECASE):
        identified_types.append("SHA1")
    if length == 56 and re.fullmatch(r"^[a-f0-9]{56}$", hash_string, re.IGNORECASE):
        identified_types.append("SHA224")
    if length == 64 and re.fullmatch(r"^[a-f0-9]{64}$", hash_string, re.IGNORECASE):
        identified_types.append("SHA256")
    if length == 96 and re.fullmatch(r"^[a-f0-9]{96}$", hash_string, re.IGNORECASE):
        identified_types.append("SHA384")
    if length == 128 and re.fullmatch(r"^[a-f0-9]{128}$", hash_string, re.IGNORECASE):
        identified_types.append("SHA512")
    if re.fullmatch(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", hash_string):
        identified_types.append("bcrypt")
    if hash_string.startswith(("$argon2i$", "$argon2d$", "$argon2id$")):
        identified_types.append("Argon2 (likely)")
    if hash_string.startswith("$s0$") or "scrypt" in hash_string.lower() and hash_string.count(":") >= 3:
        identified_types.append("scrypt (likely)")

    if not identified_types:
        return ["Unknown or unsupported hash type"]
    return identified_types

# --- Part 2: Hash Cracker ---

SUPPORTED_HASH_ALGOS_FOR_CRACKING = ["md5", "sha1", "sha256", "sha224", "sha384", "sha512"]

def get_hasher(hash_type_name):
    hash_type_name = hash_type_name.lower()
    if hash_type_name not in SUPPORTED_HASH_ALGOS_FOR_CRACKING:
        raise ValueError(f"Hash type '{hash_type_name}' is not supported for cracking by this script.")
    return getattr(hashlib, hash_type_name)


def dictionary_cracker(target_hash, hash_type, wordlist_path, encoding='utf-8'):
    cprint(f"\n[*] Starting Dictionary Attack for {hash_type.upper()} hash: {Colors.OKCYAN}{target_hash}", Colors.OKBLUE)
    cprint(f"[*] Wordlist: {Colors.OKCYAN}{wordlist_path}", Colors.OKBLUE)

    if not os.path.exists(wordlist_path):
        cprint(f"[-] Error: Wordlist file not found at '{wordlist_path}'", Colors.FAIL)
        return None
    if not os.path.isfile(wordlist_path):
        cprint(f"[-] Error: '{wordlist_path}' is not a file.", Colors.FAIL)
        return None

    found = False
    try:
        hasher_constructor = get_hasher(hash_type)
    except ValueError as e:
        cprint(f"[-] Error: {e}", Colors.FAIL)
        return None

    start_time = time.time()
    processed_lines = 0
    try:
        with open(wordlist_path, 'r', encoding=encoding, errors='ignore') as f:
            for line in f:
                processed_lines += 1
                word = line.strip()
                if not word:
                    continue

                hashed_word = hasher_constructor(word.encode(encoding)).hexdigest()

                if (processed_lines) % 100000 == 0:
                    elapsed_time = time.time() - start_time
                    cprint(f"[*] Tried {processed_lines} words... ({elapsed_time:.2f}s elapsed)", Colors.DIM, end='\r')

                if hashed_word == target_hash:
                    end_time = time.time()
                    cprint("\n[+] Password found!                             ", Colors.OKGREEN, bold=True)
                    cprint(f"    Original Text: {Colors.OKCYAN}{word}", Colors.OKGREEN)
                    cprint(f"    Hash: {Colors.OKCYAN}{target_hash}{Colors.OKGREEN} ({hash_type.upper()})", Colors.OKGREEN)
                    cprint(f"    Time taken: {end_time - start_time:.4f} seconds", Colors.OKGREEN)
                    cprint(f"    Words tried: {processed_lines}", Colors.OKGREEN)
                    found = True
                    return word
    except Exception as e:
        cprint(f"\n[-] An error occurred during dictionary attack: {e}", Colors.FAIL)
        return None
    finally:
        cprint("", end='\r') # Clear progress line

    end_time = time.time()
    if not found:
        cprint(f"\n[-] Password not found in the wordlist '{wordlist_path}'.", Colors.WARNING)
        cprint(f"[*] Words tried: {processed_lines}", Colors.DIM)
        cprint(f"[*] Time taken: {end_time - start_time:.4f} seconds", Colors.DIM)
    return None


def brute_force_cracker(target_hash, hash_type, max_length=5, charset_choice='default'):
    cprint(f"\n[*] Starting Brute-Force Attack for {hash_type.upper()} hash: {Colors.OKCYAN}{target_hash}", Colors.OKBLUE)

    cs_map = {
        'default': string.ascii_lowercase + string.digits,
        'lower': string.ascii_lowercase,
        'upper': string.ascii_uppercase,
        'digits': string.digits,
        'alnum': string.ascii_letters + string.digits,
        'alnumspecial': string.ascii_letters + string.digits + string.punctuation
    }
    charset = cs_map.get(charset_choice, charset_choice) # Use custom if not in map

    cprint(f"[*] Using charset: '{Colors.OKCYAN}{charset if len(charset) < 60 else charset_choice if charset_choice != charset else 'custom'}{Colors.OKBLUE}'", Colors.OKBLUE)
    cprint(f"[*] Maximum password length: {Colors.OKCYAN}{max_length}", Colors.OKBLUE)
    cprint(f"[*] Character set size: {Colors.OKCYAN}{len(charset)}", Colors.OKBLUE)


    found = False
    try:
        hasher_constructor = get_hasher(hash_type)
    except ValueError as e:
        cprint(f"[-] Error: {e}", Colors.FAIL)
        return None

    start_time = time.time()
    total_attempts = 0

    for length in range(1, max_length + 1):
        num_combinations = len(charset) ** length
        cprint(f"[*] Trying passwords of length {length} ({num_combinations} combinations)...", Colors.OKBLUE)
        attempts_this_length = 0
        for attempt_tuple in itertools.product(charset, repeat=length):
            attempt = "".join(attempt_tuple)
            attempts_this_length +=1
            total_attempts +=1
            hashed_attempt = hasher_constructor(attempt.encode()).hexdigest()

            if (attempts_this_length) % 200000 == 0:
                elapsed_time = time.time() - start_time
                cprint(f"[*] L{length}: {attempts_this_length}/{num_combinations} att... ({elapsed_time:.2f}s elapsed)", Colors.DIM, end='\r')

            if hashed_attempt == target_hash:
                end_time = time.time()
                cprint("\n[+] Password found!                                 ", Colors.OKGREEN, bold=True)
                cprint(f"    Original Text: {Colors.OKCYAN}{attempt}", Colors.OKGREEN)
                cprint(f"    Hash: {Colors.OKCYAN}{target_hash}{Colors.OKGREEN} ({hash_type.upper()})", Colors.OKGREEN)
                cprint(f"    Time taken: {end_time - start_time:.4f} seconds", Colors.OKGREEN)
                cprint(f"    Total attempts: {total_attempts}", Colors.OKGREEN)
                found = True
                return attempt
        if found:
            break
        cprint(f"[*] Finished length {length}. {attempts_this_length} attempts.                          ", Colors.DIM)

    end_time = time.time()
    if not found:
        cprint(f"\n[-] Password not found with current brute-force settings.", Colors.WARNING)
        cprint(f"    (max_length={max_length}, charset='{charset_choice}')", Colors.DIM)
        cprint(f"[*] Total attempts: {total_attempts}", Colors.DIM)
        cprint(f"[*] Time taken: {end_time - start_time:.4f} seconds", Colors.DIM)
    return None


# --- Main Application Logic ---
def main():
    # Optional: For Windows, if colors don't show, uncomment next two lines
    # import colorama
    # colorama.init()

    cprint("===================================================", Colors.HEADER, bold=True)
    cprint("                 Hash Identifier & Cracker         ", Colors.HEADER, bold=True)
    cprint("                  by Sher Khan                     ", Colors.OKCYAN, bold=True)
    cprint("   LinkedIn: https://www.linkedin.com/in/sherkhan-sk ", Colors.OKBLUE)
    cprint("   Contact: +923122632023                        ", Colors.OKBLUE)
    cprint("===================================================", Colors.HEADER, bold=True)
    cprint("\nDISCLAIMER: This tool is for educational purposes only.", Colors.WARNING, bold=True)
    cprint("Ensure you have authorization before testing any hashes.\n", Colors.WARNING)

    while True:
        try:
            target_hash_input = input(f"{Colors.OKBLUE}Enter the hash to identify/crack (or 'exit' to quit): {Colors.ENDC}").strip()
        except KeyboardInterrupt:
            cprint("\nExiting program due to user interrupt.", Colors.WARNING)
            break
        if not target_hash_input:
            continue
        if target_hash_input.lower() == 'exit':
            cprint("Exiting program.", Colors.OKGREEN)
            break

        cprint(f"\n[IDENTIFIER RESULT]", Colors.HEADER, bold=True)
        identified_types = identify_hash(target_hash_input)
        if not identified_types or identified_types[0] == "Unknown or unsupported hash type":
            cprint("  Could not identify hash type, or it's unsupported.", Colors.WARNING)
        else:
            cprint(f"  Possible hash type(s): {Colors.OKGREEN}{', '.join(identified_types)}", Colors.OKCYAN)

        crackable_hash_type = None
        for ht in identified_types:
            if ht.lower() in SUPPORTED_HASH_ALGOS_FOR_CRACKING:
                crackable_hash_type = ht.lower()
                break
            elif ht == "NTLM (potentially)" and "md5" in SUPPORTED_HASH_ALGOS_FOR_CRACKING:
                cprint("  Note: NTLM can be treated as MD5 for cracking.", Colors.DIM)
                if not crackable_hash_type:
                    crackable_hash_type = "md5"

        if not crackable_hash_type:
            cprint("  Cannot proceed with cracking for the identified hash type(s) with this basic script.", Colors.WARNING)
            cprint("  (Complex/salted hashes like bcrypt, Argon2, scrypt are not supported for cracking here).", Colors.DIM)
            cprint("-" * 50, Colors.HEADER)
            continue

        cprint(f"  Selected '{Colors.OKGREEN}{crackable_hash_type.upper()}{Colors.OKCYAN}' for cracking attempt.", Colors.OKCYAN)
        cprint("-" * 50, Colors.HEADER)

        while True:
            try:
                cprint("\nChoose cracking method:", Colors.OKBLUE, bold=True)
                cprint("  1. Dictionary Attack", Colors.OKCYAN)
                cprint(f"  2. Brute-Force Attack ({Colors.WARNING}WARNING: Can be very slow!{Colors.OKCYAN})", Colors.OKCYAN)
                cprint("  3. Identify a different hash", Colors.OKCYAN)
                cprint("  4. Exit", Colors.OKCYAN)
                choice = input(f"{Colors.OKBLUE}Enter choice (1-4): {Colors.ENDC}").strip()

                if choice == '1':
                    wordlist = input(f"{Colors.OKBLUE}Enter path to wordlist file: {Colors.ENDC}").strip()
                    if not wordlist:
                        cprint("[-] Wordlist path cannot be empty.", Colors.FAIL)
                        continue
                    dictionary_cracker(target_hash_input, crackable_hash_type, wordlist)
                    break
                elif choice == '2':
                    try:
                        max_len_str = input(f"{Colors.OKBLUE}Enter max password length for brute-force (e.g., 3-6, default 5): {Colors.ENDC}").strip()
                        max_len = int(max_len_str) if max_len_str else 5

                        cprint("\nSelect character set for brute-force:", Colors.OKBLUE, bold=True)
                        options = {
                            '1': ("Lowercase letters (a-z)", 'lower'),
                            '2': ("Uppercase letters (A-Z)", 'upper'),
                            '3': ("Digits (0-9)", 'digits'),
                            '4': ("Lowercase + Digits (default)", 'default'),
                            '5': ("Alphanumeric (a-z, A-Z, 0-9)", 'alnum'),
                            '6': ("Alphanumeric + Special Characters", 'alnumspecial'),
                            '7': ("Custom charset", 'custom')
                        }
                        for k, v in options.items():
                            cprint(f"  {k}. {v[0]}", Colors.OKCYAN)

                        charset_opt = input(f"{Colors.OKBLUE}Charset choice (1-7, default 4): {Colors.ENDC}").strip()
                        cs_choice = options.get(charset_opt, (None, 'default'))[1] # Default to 'default' if invalid

                        if cs_choice == 'custom':
                            custom_cs_input = input(f"{Colors.OKBLUE}Enter custom characters (e.g., abc123!@#): {Colors.ENDC}").strip()
                            if not custom_cs_input:
                                cprint("[-] Custom charset cannot be empty if selected. Using default.", Colors.WARNING)
                                cs_choice = 'default'
                            else:
                                cs_choice = custom_cs_input
                        elif not options.get(charset_opt) and charset_opt: # Invalid option but not empty
                             cprint("[-] Invalid charset option, using default (lowercase + digits).", Colors.WARNING)
                             cs_choice = 'default'


                        brute_force_cracker(target_hash_input, crackable_hash_type, max_len, cs_choice)
                        break
                    except ValueError:
                        cprint("[-] Invalid length. Please enter a number.", Colors.FAIL)
                elif choice == '3':
                    break
                elif choice == '4':
                    cprint("Exiting program.", Colors.OKGREEN)
                    return
                else:
                    cprint("[-] Invalid choice. Please enter a number between 1 and 4.", Colors.FAIL)
            except KeyboardInterrupt:
                cprint("\nReturning to main menu...", Colors.WARNING)
                break # Break from cracking method choice, back to new hash input
        cprint("-" * 50, Colors.HEADER)


if __name__ == "__main__":
    if not os.path.exists("my_test_wordlist.txt"):
        with open("my_test_wordlist.txt", "w") as f:
            f.write("test\n")
            f.write("password\n")
            f.write("123456\n")
            f.write("admin\n")
            f.write("qwerty\n")
        cprint("Created 'my_test_wordlist.txt' for dictionary attack testing.", Colors.DIM)
        cprint("You can use this or provide a path to your own wordlist.\n", Colors.DIM)

    main()
