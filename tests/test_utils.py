import pytest
import sys
import os

# Ajouter le répertoire parent au path pour les imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.validators import InputValidator
from src.utils.text_processor import TextProcessor
from src.utils.key_generator import KeyGenerator

class TestInputValidator:
    """Tests pour le validateur d'entrées."""
    
    def setup_method(self):
        """Configure les tests."""
        self.validator = InputValidator()
    
    def test_validate_text(self):
        """Teste la validation du texte."""
        # Textes valides
        assert self.validator.validate_text("Hello") is True
        assert self.validator.validate_text("123") is True
        assert self.validator.validate_text(" ") is True
        
        # Textes invalides
        assert self.validator.validate_text("") is False
        assert self.validator.validate_text(None) is False
        assert self.validator.validate_text(123) is False
    
    def test_validate_caesar_key(self):
        """Teste la validation de la clé pour César."""
        # Clés valides
        assert self.validator.validate_caesar_key("0") is True
        assert self.validator.validate_caesar_key("13") is True
        assert self.validator.validate_caesar_key("25") is True
        
        # Clés invalides
        assert self.validator.validate_caesar_key("-1") is False
        assert self.validator.validate_caesar_key("26") is False
        assert self.validator.validate_caesar_key("abc") is False
        assert self.validator.validate_caesar_key("") is False
        assert self.validator.validate_caesar_key(None) is False
    
    def test_validate_vigenere_key(self):
        """Teste la validation de la clé pour Vigenère."""
        # Clés valides
        assert self.validator.validate_vigenere_key("KEY") is True
        assert self.validator.validate_vigenere_key("Secret Key") is True
        assert self.validator.validate_vigenere_key("X") is True
        
        # Clés invalides
        assert self.validator.validate_vigenere_key("") is False
        assert self.validator.validate_vigenere_key("KEY123") is False
        assert self.validator.validate_vigenere_key(123) is False
        assert self.validator.validate_vigenere_key(None) is False
    
    def test_validate_playfair_key(self):
        """Teste la validation de la clé pour Playfair."""
        # Clés valides
        assert self.validator.validate_playfair_key("MONARCHY") is True
        assert self.validator.validate_playfair_key("Playfair Example") is True
        assert self.validator.validate_playfair_key("X") is True
        
        # Clés invalides
        assert self.validator.validate_playfair_key("") is False
        assert self.validator.validate_playfair_key("KEY123") is False
        assert self.validator.validate_playfair_key(123) is False
        assert self.validator.validate_playfair_key(None) is False


class TestTextProcessor:
    """Tests pour le processeur de texte."""
    
    def setup_method(self):
        """Configure les tests."""
        self.processor = TextProcessor()
    
    def test_clean_for_encryption(self):
        """Teste le nettoyage du texte pour le chiffrement."""
        # Sans préservation des espaces
        assert self.processor.clean_for_encryption("Hello World!") == "HELLOWORLD"
        assert self.processor.clean_for_encryption("123 ABC") == "ABC"
        
        # Avec préservation des espaces
        assert self.processor.clean_for_encryption("Hello World!", True) == "HELLO WORLD"
        assert self.processor.clean_for_encryption("123 ABC", True) == " ABC"
    
    def test_format_output(self):
        """Teste le formatage de la sortie."""
        # Formatage par blocs de 5
        assert self.processor.format_output("HELLOWORLD") == "HELLO WORLD"
        assert self.processor.format_output("ABC") == "ABC"
        assert self.processor.format_output("ABCDEFGHIJKLM") == "ABCDE FGHIJ KLM"
        
        # Formatage avec taille de bloc personnalisée
        assert self.processor.format_output("HELLOWORLD", 3) == "HEL LOW ORL D"
    
    def test_prepare_for_playfair(self):
        """Teste la préparation du texte pour le chiffrement Playfair."""
        # Test de séparation des paires identiques
        assert "HELXLO" in self.processor.prepare_for_playfair("Hello")
        
        # Test d'ajout d'un X à la fin si nécessaire
        assert self.processor.prepare_for_playfair("HELL").endswith("X")
        
        # Test de remplacement de J par I
        assert "I" in self.processor.prepare_for_playfair("J")
        assert "I" in self.processor.prepare_for_playfair("JAVA")
    
    def test_restore_playfair_text(self):
        """Teste la restauration du texte après déchiffrement Playfair."""
        # Test de suppression de X à la fin
        assert self.processor.restore_playfair_text("HELLOX") == "HELLO"
        
        # Test de suppression de X entre doublons
        assert self.processor.restore_playfair_text("HELXLO") == "HELLO"


class TestKeyGenerator:
    """Tests pour le générateur de clés."""
    
    def setup_method(self):
        """Configure les tests."""
        self.generator = KeyGenerator()
    
    def test_generate_caesar_key(self):
        """Teste la génération de clé pour César."""
        for _ in range(10):  # Tester plusieurs générations
            key = self.generator.generate_caesar_key()
            assert isinstance(key, int)
            assert 1 <= key <= 25
    
    def test_generate_vigenere_key(self):
        """Teste la génération de clé pour Vigenère."""
        # Test avec longueur par défaut
        key = self.generator.generate_vigenere_key()
        assert isinstance(key, str)
        assert len(key) == 8
        assert all(c.isalpha() and c.isupper() for c in key)
        
        # Test avec longueur personnalisée
        key = self.generator.generate_vigenere_key(5)
        assert len(key) == 5
    
    def test_generate_playfair_key(self):
        """Teste la génération de clé pour Playfair."""
        # Test avec longueur par défaut
        key = self.generator.generate_playfair_key()
        assert isinstance(key, str)
        assert len(key) == 10
        assert all(c.isalpha() and c.isupper() for c in key)
        
        # Test avec longueur personnalisée
        key = self.generator.generate_playfair_key(5)
        assert len(key) == 5
        
        # Vérifier qu'il n'y a pas de doublons dans la clé
        assert len(key) == len(set(key))
        
        # Vérifier que J n'est pas dans la clé
        assert "J" not in key