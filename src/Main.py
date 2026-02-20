# Jonathan Hernandez, Nikita Bizyuk, Vincent Xu
# TCSS 483 Secure Coding Principles
# Winter 2026, 2/20/2026
# Defend your code Team Assignment

# This is the Python translation of Main2.java, aided by PyCharm's built-in AI assistant.

"""
1) Validate ALL user inputs (names, ints, file names, passwords).
2) Never crash. The program must keep running until valid input is obtained.
3) Log ANY errors/exceptions to an error log file (error.log).
4) Prevent integer overflow for both SUM and PRODUCT (32-bit signed int).
5) Passwords must NOT be stored in plaintext.
   - Use random SALT + PBKDF2 hash
   - Write salt+hash to a file
   - For verification: READ salt+hash back from file and compare
"""

import base64
import datetime as _dt
import hashlib
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

ERROR_LOG = "error.log" # We add errors/exceptions to this file
PASSWORD_STORE = "password_store.txt" # We store salt+hash in this file
INT32_MAX = 2_147_483_647 # Python integers do not overflow but we enforce this explicitly
INT32_MIN = -2_147_483_648 # Thus we define bounds

def delimiter() -> None:
    print("\n-----------------------------------"
          "-------------------------------------\n")

def log_error(message: str, exc: Optional[BaseException] = None) -> None:
    """
    Writes error messages (and optional exception) to error.log.

    Critical requirement:
    - DO NOT throw exceptions from logger.
      If logging fails, we ignore it to prevent a program crash.
    """
    try:
        ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(ERROR_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {message}\n")
            if exc is not None:
                f.write(f"Exception: {exc!r}\n")
            f.write("\n")
    except OSError:
        # Never crash from the logger.
        pass

def validate_name(first_last_name: str) -> str:
    # Allows letters, hyphen, apostrophe; length 1..50
    pattern = re.compile(r"[A-Za-z-']{1,50}")

    requirements = (
        "Input must meet following requirements:\n"
        "\t1) Input must include characters (A-Z or a-z) inclusive.\n"
        "\t2) Special characters such as (- and ') are permitted.\n"
        "\t3) input length must be >= 1 and <= 50\n"
    )

    delimiter()
    print(f"\nPLEASE ENTER YOUR {first_last_name}:\n"
          f"{requirements}\nENTER {first_last_name}:")

    name = input()
    while not pattern.fullmatch(name):
        delimiter()
        print("HOUSTON WE HAVE A PROBLEM! "
              f"{requirements}\t{name}"
              "\tDoes not meet the following requirements."
              "\n\tPlease try again!")
        name = input()

    return name

def validate_regex_value(user_input: str, pattern: re.Pattern, requirements: str, int_val_label: str) -> str:
    while not pattern.fullmatch(user_input):
        delimiter()
        print("\tYour input does not match the requirements listed above.\n"
              f"\tPLEASE ENTER A VALUE FOR {int_val_label}"
              f"\n{requirements}\n{int_val_label}:")
        user_input = input()

    return user_input.replace(",", "")

def verify_bounds(pattern: re.Pattern, requirements: str, int_val_label: str, value: int) -> int:
    while value > INT32_MAX or value < INT32_MIN:
        delimiter()
        if value > INT32_MAX:
            print("Your input was greater then the value of 2,147,483,647\n"
                  "\tthis will result in an integer overflow.\n"
                  "Please try again:")
        else:
            print("Your input was less then the value of -2,147,483,648\n"
                  "this will result in an integer overflow.\n"
                  "Please try again:")

        user_input = input()
        cleaned = validate_regex_value(user_input, pattern, requirements, int_val_label)

        # Python int doesn't overflow, but we enforce int32 bounds explicitly.
        try:
            value = int(cleaned)
        except ValueError as e:
            # Shouldn't happen if regex is correct, but keep it defensive.
            log_error("Unexpected int parse failure after regex validation.", e)
            value = INT32_MAX + 1

    return value

def validate_int_value(int_val_label: str) -> int:
    requirements = "value must be inclusive between -2,147,483,648  to  2,147,483,647"
    prompt_user = (f"PLEASE ENTER A VALUE FOR {int_val_label}\n"
                   f"{requirements}\n{int_val_label}:")

    # Allows comma formatting (e.g., 1,000). Then commas are removed.
    pattern = re.compile(r"^[+-]?(?:\d{1,3}(?:,\d{3})*|\d+)$")

    delimiter()
    print(prompt_user)
    user_input = input()

    cleaned = validate_regex_value(user_input, pattern, requirements, int_val_label)

    try:
        value = int(cleaned)
    except ValueError as e:
        # Defensive: regex should prevent this.
        log_error(f"Failed to parse integer for {int_val_label}: {cleaned}", e)
        value = INT32_MAX + 1

    return verify_bounds(pattern, requirements, int_val_label, value)

def verify_txt_file(io_label: str) -> str:
    requirements = (
        "-File type (.txt) accepted only.\n"
        "-Naming conventions allow for characters A-Z,0-9, special characters such as\n"
        "(._-)\n"
        "-length of file name must be greater than or equal to 1"
    )
    pattern = re.compile(r"^[A-Za-z0-9._-]+\.txt$")

    delimiter()
    print(f"\nPlease enter an {io_label} name that matches the requirements listed below: \n"
          f"{requirements}\n"
          f"Enter {io_label} name: ")
    user_input = input()

    while not pattern.fullmatch(user_input):
        delimiter()
        print("File name or type does not follow the requirements listed below: \n"
              f"{requirements}\n"
              f"Please enter {io_label} file name here: ")
        user_input = input()

    return user_input

def fits_int32(v: int) -> bool:
    return INT32_MIN <= v <= INT32_MAX

def verify_existing_readable_input_file(file_name: str) -> str:
    while True:
        try:
            p = Path(file_name)

            # Must exist, must be a regular file, must be readable
            if p.exists() and p.is_file():
                try:
                    with open(p, "rb"):
                        pass
                    return file_name
                except OSError:
                    pass

            log_error(f"Input file missing/unreadable: {file_name}", None)
            print("Input file must exist and be readable. Please enter again.")
            file_name = verify_txt_file("Input File")

        except Exception as e:
            log_error(f"Error validating input file: {file_name}", e)
            print("Error validating input file. Please try again.")
            file_name = verify_txt_file("Input File")

def can_write_file(file_name: str) -> bool:
    p = Path(file_name)

    if p.exists():
        return p.is_file() and os.access(p, os.W_OK)

    parent = p.parent if str(p.parent) not in ("", ".") else Path(".")
    return parent.exists() and parent.is_dir() and os.access(parent, os.W_OK)

def verify_writable_output_file(file_name: str) -> str:
    while True:
        try:
            if can_write_file(file_name):
                return file_name

            log_error(f"Output file not writable/creatable: {file_name}", None)
            print("Output file is not writable/creatable. Please enter again.")
            file_name = verify_txt_file("Output File")

        except Exception as e:
            log_error(f"Error validating output file: {file_name}", e)
            print("Error validating output file. Please try again.")
            file_name = verify_txt_file("Output File")

def read_file_contents_with_retry(input_file_name: str) -> str:
    while True:
        try:
            return Path(input_file_name).read_text(encoding="utf-8")
        except OSError as e:
            log_error(f"Failed to read input file: {input_file_name}", e)
            print("Failed to read input file. Please re-enter input file name.")
            input_file_name = verify_txt_file("Input File")
            input_file_name = verify_existing_readable_input_file(input_file_name)

def write_output_file_with_retry(
    output_file_name: str,
    first_name: str,
    last_name: str,
    a: int,
    b: int,
    sum_value: int,
    product_value: int,
    input_file_name: str,
    input_file_contents: str,
) -> None:
    while True:
        try:
            with open(output_file_name, "w", encoding="utf-8", newline="\n") as f:
                f.write(f"First Name: {first_name}\n")
                f.write(f"Last Name: {last_name}\n")
                f.write(f"First Integer: {a}\n")
                f.write(f"Second Integer: {b}\n")
                f.write(f"Sum: {sum_value}\n")
                f.write(f"Product: {product_value}\n")
                f.write(f"Input File Name: {input_file_name}\n\n")

                f.write("---- BEGIN INPUT FILE CONTENTS ----\n")
                f.write(input_file_contents)
                if not input_file_contents.endswith("\n"):
                    f.write("\n")
                f.write("---- END INPUT FILE CONTENTS ----\n")
            return

        except OSError as e:
            log_error(f"Failed to write output file: {output_file_name}", e)
            print("Failed to write output file. Please re-enter output file name.")
            output_file_name = verify_txt_file("Output File")
            output_file_name = verify_writable_output_file(output_file_name)

def is_valid_password(pwd: Optional[str]) -> bool:
    # length 8..64, must include upper/lower/digit/special, no whitespace
    if pwd is None:
        return False
    return re.fullmatch(r"^(?=.{8,64}$)(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9])\S+$", pwd) is not None

def generate_salt(length: int) -> bytes:
    return secrets.token_bytes(length)

def pbkdf2_hash(password: str, salt: bytes) -> Optional[bytes]:
    try:
        # PBKDF2WithHmacSHA256 equivalent
        # iterations=65536, dklen=32 bytes (256-bit)
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 65536, dklen=32)
    except Exception as e:
        log_error("PBKDF2 error.", e)
        return None

def write_password_store(salt: bytes, hash_bytes: bytes) -> None:
    try:
        with open(PASSWORD_STORE, "w", encoding="utf-8", newline="\n") as f:
            f.write("salt=" + base64.b64encode(salt).decode("ascii") + "\n")
            f.write("hash=" + base64.b64encode(hash_bytes).decode("ascii") + "\n")
    except OSError as e:
        log_error("Failed to write password store.", e)

@dataclass(frozen=True)
class PasswordRecord:
    salt: bytes
    hash: bytes

def read_password_store() -> Optional[PasswordRecord]:
    try:
        salt_line = None
        hash_line = None

        with open(PASSWORD_STORE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("salt="):
                    salt_line = line[len("salt="):].strip()
                elif line.startswith("hash="):
                    hash_line = line[len("hash="):].strip()

        if not salt_line or not hash_line:
            return None

        salt = base64.b64decode(salt_line)
        hash_bytes = base64.b64decode(hash_line)
        return PasswordRecord(salt=salt, hash=hash_bytes)

    except Exception as e:
        log_error("Failed to read password store.", e)
        return None

def handle_password_flow() -> None:
    while True:
        try:
            print("\nEnter password (8-64 chars; must include upper, lower, digit, special; no spaces):")
            p1 = input()

            if not is_valid_password(p1):
                log_error("Password failed validation rules.", None)
                print(" Password does not meet requirements. Try again.")
                continue

            salt = generate_salt(16)

            hash1 = pbkdf2_hash(p1, salt)
            if hash1 is None:
                log_error("Password hashing failed.", None)
                print("Hashing failed. Try again.")
                continue

            write_password_store(salt, hash1)

            record = read_password_store()
            if record is None:
                log_error("Failed to read password store for verification.", None)
                print("Could not read password store. Try again.")
                continue

            print("Re-enter password to verify:")
            p2 = input()

            hash2 = pbkdf2_hash(p2, record.salt)
            if hash2 is None:
                log_error("Password verification hashing failed.", None)
                print("Hashing failed. Try again.")
                continue

            if secrets.compare_digest(record.hash, hash2):
                print("Password verified.")
                return

            log_error("Password mismatch.", None)
            print("Passwords did not match. Start over.")

        except Exception as e:
            log_error("Error in password flow.", e)
            print("Password flow error. Try again.")

def main() -> None:
    first_name = validate_name("FIRST NAME")
    last_name = validate_name("LAST NAME")

    # Read two int values (must be 32-bit signed int) + ensure sum/product also fit int32
    while True:
        a = validate_int_value("Value 1")
        b = validate_int_value("Value 2")

        sum_big = a + b
        prod_big = a * b

        if fits_int32(sum_big) and fits_int32(prod_big):
            sum_value = int(sum_big)
            product_value = int(prod_big)
            break

        log_error(f"Sum/Product overflow for a={a}, b={b}", None)
        print(" Sum or product would overflow a 32-bit int. Please re-enter BOTH integers.")

    input_file_name = verify_txt_file("Input File")
    input_file_name = verify_existing_readable_input_file(input_file_name)
    input_file_contents = read_file_contents_with_retry(input_file_name)

    output_file_name = verify_txt_file("Output File")
    output_file_name = verify_writable_output_file(output_file_name)

    handle_password_flow()

    write_output_file_with_retry(
        output_file_name,
        first_name,
        last_name,
        a,
        b,
        sum_value,
        product_value,
        input_file_name,
        input_file_contents,
    )

    print(f"All inputs validated. Output written to: {output_file_name}")

if __name__ == "__main__":
    main()