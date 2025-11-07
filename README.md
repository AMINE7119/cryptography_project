# Cryptography Education Suite

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![Tests](https://img.shields.io/badge/tests-115%20passing-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)

A comprehensive educational cryptography project demonstrating the evolution from classical ciphers to modern password security. This project implements historical encryption algorithms, cryptanalysis tools, modern hashing methods, and professional password auditing techniques.

## Overview

This project serves as a complete learning path through cryptography history and modern security practices, divided into four progressive phases:

1. **Classical Encryption** - Implementation of historical ciphers
2. **Cryptanalysis** - Tools to break classical encryption
3. **Modern Hashing** - Secure password storage methods
4. **Password Auditing** - Professional password cracking integration

## Features

### Phase 1: Classical Encryption Algorithms

Three classical cipher implementations with full encrypt/decrypt capabilities:

- **Caesar Cipher** - Simple substitution cipher using alphabet shifts (used by Julius Caesar)
- **Vigenère Cipher** - Polyalphabetic substitution using keyword-based encryption
- **Playfair Cipher** - Digraph substitution cipher with 5×5 matrix (WWI military cipher)

### Phase 2: Cryptanalysis Tools

Comprehensive cipher-breaking capabilities demonstrating why classical ciphers are insecure:

- **Frequency Analysis Engine**
  - Letter frequency counting and chi-squared scoring
  - Index of Coincidence (IC) calculation
  - Support for French and English frequency tables

- **Caesar Cipher Breaking**
  - Brute force attack (< 0.01 seconds)
  - Frequency-based attack
  - Known plaintext attack

- **Vigenère Cipher Breaking**
  - Kasiski examination for key length detection
  - Index of Coincidence attack
  - Automatic key recovery and plaintext extraction

### Phase 3: Modern Password Hashing

Implementation of modern cryptographic hash functions and password security concepts:

- **Hash Algorithms**
  - MD5 (obsolete - educational only)
  - SHA-1 (deprecated - educational only)
  - SHA-256 (modern, secure)
  - SHA-512 (very secure)
  - bcrypt (recommended for passwords)

- **Security Concepts**
  - Cryptographic salt generation
  - Pepper (application-wide secret)
  - PBKDF2 key derivation (100,000+ iterations)
  - Rainbow table attack simulation
  - Password database with security scoring

- **Performance Analysis**
  - Algorithm speed comparison
  - Collision resistance demonstration
  - Security trade-offs explanation

### Phase 4: Password Auditing with John the Ripper

Professional password cracking tool integration for security testing:

- **Python Wrapper** - Complete interface to John the Ripper CLI
- **Hash File Generation** - Export to JtR-compatible formats (MD5, SHA-256, bcrypt)
- **Wordlist Management** - 100+ common passwords with pattern generation
- **Result Analysis** - Password strength scoring and crack rate statistics
- **Educational Demonstrations** - Showing vulnerabilities of weak hashing methods

## Installation

### Prerequisites

- Python 3.6 or higher
- pip package manager

### Required Dependencies

```bash
# Clone the repository
git clone https://github.com/AMINE7119/cryptography_project.git
cd cryptography_project

# Install Python dependencies
pip install -r requirements.txt
```

### Optional: John the Ripper (for Phase 4)

```bash
# Ubuntu/Debian
sudo apt-get install john

# macOS
brew install john

# Windows
# Download from https://www.openwall.com/john/
```

## Usage

### Command Line Interface

The CLI provides interactive menus for all features:

```bash
python src/interface/cli.py
```

**Menu Options:**
1. Encrypt a message (Caesar, Vigenère, Playfair)
2. Decrypt a message
3. Cryptanalysis (break encryption)
4. Frequency analysis
5. Modern hashing (password storage)
6. John the Ripper (password auditing)

### Graphical User Interface

```bash
python src/interface/gui.py
```

### Programmatic Usage

```python
# Example 1: Classical encryption
from src.algorithms.caesar import CaesarCipher

cipher = CaesarCipher()
encrypted = cipher.encrypt("HELLO WORLD", 3)
print(encrypted)  # KHOOR ZRUOG

# Example 2: Breaking Caesar cipher
from src.cryptanalysis.caesar_breaker import CaesarBreaker

breaker = CaesarBreaker()
results = breaker.brute_force("KHOOR ZRUOG")
print(results[0])  # {'key': 3, 'text': 'HELLO WORLD', ...}

# Example 3: Modern password hashing
from src.hashing.password_manager import PasswordDatabase

db = PasswordDatabase()
db.add_user('alice', 'secure_password', method='bcrypt')
success = db.login('alice', 'secure_password')
print(success)  # True
```

## Testing

Comprehensive test suite with 115 tests covering all functionality:

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_caesar.py
pytest tests/test_cryptanalysis.py
pytest tests/test_hashing.py
pytest tests/test_john_ripper.py

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=src --cov-report=term-missing
```

## Examples and Demonstrations

### Phase 2 Demo: Cryptanalysis
```bash
python examples/cryptanalysis_demo.py
```
Interactive demonstrations of breaking Caesar and Vigenère ciphers.

### Phase 3 Demo: Modern Hashing
```bash
python examples/hashing_demo.py
```
Eight comprehensive demonstrations including:
- Hash algorithm comparison
- Collision resistance testing
- Rainbow table attacks
- Password database security analysis
- Performance benchmarks

### Phase 4 Demo: Password Auditing
```bash
python examples/john_ripper_demo.py
```
Seven demonstrations showing:
- Hash file generation
- Wordlist creation
- Password cracking workflows
- Security vulnerability analysis

## Project Structure

```
cryptography_project/
├── src/
│   ├── algorithms/          # Cipher implementations
│   │   ├── base.py          # Abstract base class
│   │   ├── caesar.py        # Caesar cipher
│   │   ├── vigenere.py      # Vigenère cipher
│   │   └── playfair.py      # Playfair cipher
│   │
│   ├── cryptanalysis/       # Cipher breaking tools
│   │   ├── frequency_analysis.py
│   │   ├── caesar_breaker.py
│   │   └── vigenere_breaker.py
│   │
│   ├── hashing/             # Modern password hashing
│   │   ├── hash_algorithms.py
│   │   ├── salt_pepper.py
│   │   └── password_manager.py
│   │
│   ├── john_ripper/         # JtR integration
│   │   ├── jtr_wrapper.py
│   │   ├── hash_file_generator.py
│   │   ├── wordlist_manager.py
│   │   └── result_parser.py
│   │
│   ├── core/                # Core engine
│   │   ├── crypto_engine.py
│   │   └── config.py
│   │
│   ├── utils/               # Utilities
│   │   ├── text_processor.py
│   │   ├── validators.py
│   │   └── key_generator.py
│   │
│   └── interface/           # User interfaces
│       ├── cli.py           # Command-line interface
│       └── gui.py           # Graphical interface
│
├── tests/                   # Comprehensive test suite (115 tests)
│   ├── test_caesar.py
│   ├── test_vigenere.py
│   ├── test_playfair.py
│   ├── test_cryptanalysis.py
│   ├── test_hashing.py
│   └── test_john_ripper.py
│
├── examples/                # Educational demonstrations
│   ├── cryptanalysis_demo.py
│   ├── hashing_demo.py
│   └── john_ripper_demo.py
│
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Architecture

The project follows object-oriented design principles with a modular architecture:

- **Abstract Base Class**: All ciphers inherit from `CipherAlgorithm` with standardized interfaces
- **Separation of Concerns**: Algorithms, analysis, UI, and utilities are cleanly separated
- **Extensibility**: Easy to add new algorithms or attack methods
- **Test Coverage**: Comprehensive unit tests for all components

## Key Educational Concepts

### Cryptography Evolution
- Classical ciphers (Caesar, Vigenère, Playfair)
- Frequency analysis and pattern recognition
- Transition from encryption to hashing
- Modern password security best practices

### Security Lessons
1. **Caesar Cipher**: Trivially broken by brute force (25 possible keys)
2. **Vigenère Cipher**: Defeated by Kasiski examination and IC analysis
3. **MD5/SHA-1**: Vulnerable to rainbow tables and GPU cracking
4. **bcrypt**: Intentional slowness provides real security

### Performance Trade-offs
- **MD5**: ~294,000 hashes/second (DANGEROUS - enables brute force)
- **bcrypt**: ~20 hashes/second (SECURE - blocks brute force)
- For 1 million password attempts:
  - MD5: ~10 seconds
  - bcrypt: ~14 hours

## Security Warnings

**IMPORTANT NOTES:**

1. **Classical Ciphers** (Phase 1-2): These are historical algorithms that can be broken in seconds. Never use them to protect real data.

2. **Weak Hash Functions** (Phase 3): MD5 and SHA-1 are broken and should never be used for password storage in production.

3. **Password Auditing** (Phase 4): John the Ripper integration is for educational and authorized security testing only. Unauthorized password cracking is illegal.

4. **Production Use**: For real applications, use:
   - bcrypt, scrypt, or Argon2 for password hashing
   - TLS/SSL for communication encryption
   - Proper key management and security practices

## Ethical Use

This project is designed for:
- ✓ Educational purposes
- ✓ Understanding cryptography history
- ✓ Learning security concepts
- ✓ Authorized security testing

It should NOT be used for:
- ✗ Unauthorized system access
- ✗ Malicious activities
- ✗ Protecting sensitive data with weak algorithms
- ✗ Any illegal activities

## Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-algorithm`)
3. Make your changes with tests
4. Run the test suite (`pytest`)
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Historical cipher algorithms based on well-documented cryptographic methods
- Modern hashing implementations follow industry best practices
- John the Ripper is developed by Openwall (https://www.openwall.com/john/)

## Contact

For questions, suggestions, or collaboration:
- GitHub Issues: [Report bugs or request features](https://github.com/AMINE7119/cryptography_project/issues)
- GitHub Profile: [@AMINE7119](https://github.com/AMINE7119)

---

**Educational Project** - Developed for learning cryptography concepts from classical ciphers to modern password security.
