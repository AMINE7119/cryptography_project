import pytest
import sys
import os

# Ajouter le répertoire parent au path pour les imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.algorithms.vigenere import VigenereCipher

class TestVigenereCipher:
    """Tests pour l'algorithme de chiffrement de Vigenère."""
    
    def setup_method(self):
        """Configure les tests."""
        self.cipher = VigenereCipher()
    
    def test_validate_key(self):
        """Teste la validation de clé."""
        # Clés valides
        assert self.cipher.validate_key("KEY") is True
        assert self.cipher.validate_key("SECRETKEY") is True
        assert self.cipher.validate_key("X") is True  # Clé d'un seul caractère
        
        # Clés invalides
        assert self.cipher.validate_key("") is False
        assert self.cipher.validate_key("KEY123") is False  # Contient des chiffres
        assert self.cipher.validate_key(123) is False  # Pas une chaîne
        assert self.cipher.validate_key(None) is False
    
    def test_encrypt(self):
        """Teste le chiffrement."""
        # Test avec la clé "KEY"
        assert self.cipher.encrypt("HELLO", "KEY") == "RIJVS"
        
        # Test avec conversion en majuscules
        assert self.cipher.encrypt("hello", "key") == "RIJVS"
        
        # Test avec suppression des espaces
        assert self.cipher.encrypt("HELLO WORLD", "KEY") == "RIJVSUYVJN"
        
        # Test avec une clé plus longue
        assert self.cipher.encrypt("HELLO", "SECRETKEY") == "ZINCS"
    
    def test_decrypt(self):
        """Teste le déchiffrement."""
        # Test avec la clé "KEY"
        assert self.cipher.decrypt("RIJVS", "KEY") == "HELLO"
        
        # Test avec conversion en majuscules
        assert self.cipher.decrypt("rijvs", "key") == "HELLO"
        
        # Test avec suppression des espaces
        assert self.cipher.decrypt("RIJVS UYVJN", "KEY") == "HELLOWORLD"
        
        # Test avec une clé plus longue
        assert self.cipher.decrypt("ZINCS", "SECRETKEY") == "HELLO"
    
    def test_encrypt_decrypt_consistency(self):
        """Teste la cohérence entre chiffrement et déchiffrement."""
        keys = ["KEY", "SECRET", "CRYPTOGRAPHY", "X"]
        texts = ["HELLO", "CRYPTOGRAPHY", "THISISASECRETMESSAGE"]
        
        for key in keys:
            for text in texts:
                encrypted = self.cipher.encrypt(text, key)
                decrypted = self.cipher.decrypt(encrypted, key)
                assert decrypted == text
    
    def test_invalid_key_raises_error(self):
        """Teste que les clés invalides lèvent des exceptions."""
        with pytest.raises(ValueError):
            self.cipher.encrypt("HELLO", "")
        
        with pytest.raises(ValueError):
            self.cipher.encrypt("HELLO", "KEY123")
        
        with pytest.raises(ValueError):
            self.cipher.decrypt("HELLO", 123)