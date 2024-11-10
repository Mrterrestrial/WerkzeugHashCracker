# Dictionary Attack Tool for Werkzeug Password Hashes

A high-performance, multiprocessing-based dictionary attack tool designed to crack Werkzeug-hashed passwords using custom or default wordlists. Built for ethical hacking and educational purposes, this tool efficiently distributes the workload across CPU cores, making it highly effective for hash-cracking tasks.


## Features
- Supports parallel processing to maximize efficiency on multi-core systems.
- Allows custom wordlists for flexible dictionary attacks.
- Simple command-line interface with clear options.

## Requirements
- Python 3.6+
- `werkzeug` library

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Mrterrestrial/WerkzeugHashCracker.git
   cd dictionary-attack-tool
   ```
2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage
```bash
python script_name.py <hashed_password> [-w WORDLIST]
```

## Arguments
- hashed_password (required): The Werkzeug-hashed password you want to crack.
- `-w`, `--wordlist` (optional): Path to the wordlist file. Defaults to `Wordlist/rockyou.txt`

## Examples
1. Using Default Wordlist:
```bash
python3 app.py pbkdf2:sha256:260000$abc123$...
```
2. Using Custom Wordlist:
```bash
python3 app.py pbkdf2:sha256:260000$abc123$... -w Path/To/custom_wordlist.txt

```


## How It Works

Werkzeug hashes are non-reversible, meaning you cannot convert a hashed password back to its plaintext form directly. Instead, this tool uses a dictionary attack to crack the password by comparing each word in a wordlist against the hash until a match is found. Werkzeug’s `check_password_hash` function allows us to check each word from the wordlist against the hashed password.

Here’s a simple example of how Werkzeug creates and verifies password hashes:

#### Hashing Process
Werkzeug uses PBKDF2 (Password-Based Key Derivation Function 2) with SHA-256 as the hashing algorithm. When creating a hash, it generates a salt and applies a series of iterations to increase security. Here’s how a password is hashed in Werkzeug:

```bash 
from werkzeug.security import generate_password_hash

# Example of hashing a password
password = "mypassword"
hashed_password = generate_password_hash(password)
print("Hashed Password:", hashed_password)
```

#### Checking Process

The `check_password_hash` function allows us to verify if a given password matches the hashed password. In the dictionary attack, this function is applied to each word in the wordlist to see if it returns `True`, indicating a match.

```bash
from werkzeug.security import check_password_hash

# Verify the password against the hashed version
password_attempt = "mypassword"
is_match = check_password_hash(hashed_password, password_attempt)
print("Does it match?", is_match)  # True if correct, False otherwise
```

#### Attack Strategy

The dictionary attack performs the following steps:

- Load the wordlist, breaking it into chunks to manage memory.
- Distribute the wordlist chunks across multiple processes to test each word in parallel.
- For each word, `check_password_hash` is used to test if it matches the target hash.
- If a match is found, the attack stops, and the plaintext password is returned.


## Disclaimer

This script is intended for educational purposes and ethical hacking. It should only be used in environments where you have explicit permission to test. The author is not responsible for any misuse of this tool.


## License

This project is licensed under the MIT License - see [MIT License](https://opensource.org/licenses/MIT) for details.

## Contributing

Feel free to fork the repository and submit pull requests. For any issues or feature requests, please open an issue on GitHub.