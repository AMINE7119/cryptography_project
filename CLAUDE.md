# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an educational cryptography project implementing classical cipher algorithms (Caesar, Vigenère, and Playfair) **with comprehensive cryptanalysis capabilities**. The codebase is written in Python and follows object-oriented design principles with a modular architecture. All documentation and comments are in French.

**Phase 1: Classical Encryption** ✓ Complete
**Phase 2: Classical Cryptanalysis** ✓ Complete
**Phase 3: Modern Hashing** → Next phase
**Phase 4: John the Ripper Integration** → Planned

## Development Commands

### Running the Application
```bash
# CLI interface
python src/interface/cli.py

# GUI interface
python src/interface/gui.py
```

### Testing
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_caesar.py
pytest tests/test_vigenere.py
pytest tests/test_playfair.py
pytest tests/test_cryptanalysis.py  # NEW: Cryptanalysis tests

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=src

# Run cryptanalysis demo
python examples/cryptanalysis_demo.py
```

### Dependencies
```bash
# Install dependencies
pip install -r requirements.txt
```

## Architecture

### Core Design Pattern

All cipher algorithms inherit from the abstract base class `CipherAlgorithm` (src/algorithms/base.py), which defines three mandatory methods:
- `encrypt(text: str, key: Any) -> str`
- `decrypt(text: str, key: Any) -> str`
- `validate_key(key: Any) -> bool`

### Module Structure

**src/algorithms/** - Cipher implementations
- `base.py`: Abstract base class `CipherAlgorithm` defining the contract for all ciphers
- `caesar.py`: Caesar cipher (shift cipher with integer key 0-25)
- `vigenere.py`: Vigenère cipher (polyalphabetic substitution with string key)
- `playfair.py`: Playfair cipher (digraph substitution using 5x5 matrix)

**src/core/** - Central coordination logic
- `crypto_engine.py`: The `CryptoEngine` class acts as the main orchestrator that:
  - Maintains a dictionary of available algorithm instances
  - Routes encrypt/decrypt requests to the appropriate algorithm
  - Applies text preprocessing and formatting via `TextProcessor`
  - Validates keys before processing
- `config.py`: Configuration constants including `ALGORITHMS` metadata dictionary

**src/utils/** - Support utilities
- `text_processor.py`: Static methods for text cleaning, block formatting (default 5-char blocks), and Playfair-specific text preparation
- `key_generator.py`: Key generation utilities
- `validators.py`: Input validation helpers

**src/interface/** - User interfaces
- `cli.py`: Command-line interface with cryptanalysis menu
- `gui.py`: Graphical user interface

**src/cryptanalysis/** - NEW: Cipher breaking tools
- `frequency_analysis.py`: Statistical analysis engine for breaking ciphers
  - Letter frequency counting and chi-squared scoring
  - Index of Coincidence (IC) calculation (detects mono vs polyalphabetic)
  - Kasiski examination (finds repeating sequences)
  - Support for French and English frequency tables
- `caesar_breaker.py`: Caesar cipher breaker
  - Brute force attack (tries all 25 keys in < 1 second)
  - Frequency attack (assumes 'E' is most common)
  - Known word attack
  - Automatic ranking by chi-squared score
- `vigenere_breaker.py`: Vigenère cipher breaker
  - Kasiski examination for key length detection
  - Index of Coincidence attack
  - Treats each position as Caesar cipher after finding key length
  - Key refinement algorithm to optimize results

**tests/** - Unit tests mirror the algorithms structure
**examples/** - Demonstration scripts
- `cryptanalysis_demo.py`: Interactive demonstrations of breaking ciphers

### Key Implementation Details

**Playfair Cipher Specifics:**
- Uses a 5x5 matrix built from the key (J is replaced with I throughout)
- Text preparation: doubles are separated with 'X', odd-length text is padded with 'X'
- Encryption rules differ for same-row, same-column, and rectangle letter pairs
- The `_create_matrix()`, `_find_position()`, and `_prepare_text()` helper methods handle the complex setup

**Text Processing Flow:**
1. User input → `CryptoEngine.encrypt()` or `decrypt()`
2. Key validation via algorithm's `validate_key()`
3. Text preprocessing (spaces removed, uppercase conversion)
4. Algorithm-specific encryption/decryption
5. Output formatting via `TextProcessor.format_output()` (5-character blocks by default)

**Import Path Note:**
- Tests add parent directory to `sys.path` to import from `src/`
- Core module imports use relative paths (e.g., `from algorithms.caesar import CaesarCipher`)

## Adding New Cipher Algorithms

1. Create new file in `src/algorithms/` (e.g., `new_cipher.py`)
2. Inherit from `CipherAlgorithm` and implement the three abstract methods
3. Add algorithm metadata to `ALGORITHMS` dict in `src/core/config.py`
4. Register instance in `CryptoEngine.__init__()` algorithms dictionary
5. Create corresponding test file in `tests/test_new_cipher.py`

## Testing Conventions

- Tests use pytest framework
- Each algorithm has a dedicated test file with a test class (e.g., `TestCaesarCipher`)
- Standard test patterns:
  - `test_validate_key()`: Test key validation logic
  - `test_encrypt()`: Test encryption with various inputs
  - `test_decrypt()`: Test decryption
  - `test_encrypt_decrypt_consistency()`: Round-trip verification
  - `test_invalid_key_raises_error()`: Error handling with pytest.raises()

## Important Notes

- This is an educational project; these classical ciphers are NOT secure for modern use
- All text processing converts to uppercase and removes non-alphabetic characters by default
- The Playfair cipher replaces 'J' with 'I' (standard 5x5 matrix limitation)
- Output text is formatted in 5-character blocks for readability (configurable via `DEFAULT_BLOCK_SIZE` in config.py)

## Cryptanalysis Capabilities

The project now includes powerful cryptanalysis tools that demonstrate why classical ciphers are insecure:

**Caesar Cipher Breaking:**
- Brute force: < 0.01 seconds (only 25 keys to try)
- Success rate: 100% for any text length
- Methods: Brute force, frequency analysis, known plaintext

**Vigenère Cipher Breaking:**
- Break time: 0.1-3 seconds (depending on key length and text length)
- Success rate: 60-90% (depends on text length and language match)
- Methods: Kasiski examination, Index of Coincidence, frequency analysis
- Minimum text length: ~100 characters for reliable results

**Statistical Analysis:**
- Chi-squared test compares observed vs expected letter frequencies
- Index of Coincidence (IC) distinguishes monoalphabetic from polyalphabetic
  - IC ≈ 0.065 for plaintext (French/English)
  - IC ≈ 0.038 for random/polyalphabetic ciphertext
- Kasiski examination finds repeated sequences to determine key length

**CLI Commands:**
```bash
# Launch CLI and select option 3 for cryptanalysis
python src/interface/cli.py
> 3  # Cryptanalyse

# Or option 4 for frequency analysis
> 4  # Analyse de fréquence
```
