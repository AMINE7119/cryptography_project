import pytest
import sys
import os

# Ajouter le répertoire parent au path pour les imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.algorithms.caesar import CaesarCipher

class TestCaesarCipher:
    """Tests pour l'algorithme de chiffrement de César."""
    
    def setup_method(self):
        """Configure les tests."""
        self.cipher = CaesarCipher()
    
    def test_validate_key(self):
        """Teste la validation de clé."""
        # Clés valides
        assert self.cipher.validate_key(0) is True
        assert self.cipher.validate_key(13) is True
        assert self.cipher.validate_key(25) is True
        assert self.cipher.validate_key("3") is True  # Conversion de chaîne en entier
        
        # Clés invalides
        assert self.cipher.validate_key(-1) is False
        assert self.cipher.validate_key(26) is False
        assert self.cipher.validate_key("abc") is False
        assert self.cipher.validate_key(None) is False
    
    def test_encrypt(self):
        """Teste le chiffrement."""
        # Test avec décalage 3
        assert self.cipher.encrypt("HELLO", 3) == "KHOOR"
        assert self.cipher.encrypt("hello", 3) == "KHOOR"  # Test conversion en majuscules
        assert self.cipher.encrypt("HELLO WORLD", 3) == "KHOORZRUOG"  # Test suppression des espaces
        
        # Test avec décalage 0 (pas de changement)
        assert self.cipher.encrypt("HELLO", 0) == "HELLO"
        
        # Test avec décalage 25 (équivalent à -1)
        assert self.cipher.encrypt("HELLO", 25) == "GDKKN"
        
        # Test avec caractères non alphabétiques
        assert self.cipher.encrypt("HELLO123", 3) == "KHOOR123"
    
    def test_decrypt(self):
        """Teste le déchiffrement."""
        # Test avec décalage 3
        assert self.cipher.decrypt("KHOOR", 3) == "HELLO"
        
        # Test avec décalage 0 (pas de changement)
        assert self.cipher.decrypt("HELLO", 0) == "HELLO"
        
        # Test avec décalage 25
        assert self.cipher.decrypt("GDKKN", 25) == "HELLO"
    
    def test_encrypt_decrypt_consistency(self):
        """Teste la cohérence entre chiffrement et déchiffrement."""
        for key in range(0, 26):
            original = "CRYPTOGRAPHY"
            encrypted = self.cipher.encrypt(original, key)
            decrypted = self.cipher.decrypt(encrypted, key)
            assert decrypted == original
    
    def test_invalid_key_raises_error(self):
        """Teste que les clés invalides lèvent des exceptions."""
        with pytest.raises(ValueError):
            self.cipher.encrypt("HELLO", -1)
        
        with pytest.raises(ValueError):
            self.cipher.encrypt("HELLO", 26)
        
        with pytest.raises(ValueError):
            self.cipher.decrypt("HELLO", "invalid")