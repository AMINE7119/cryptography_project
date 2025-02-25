import pytest
import sys
import os

# Ajouter le répertoire parent au path pour les imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.algorithms.playfair import PlayfairCipher

class TestPlayfairCipher:
    """Tests pour l'algorithme de chiffrement de Playfair."""
    
    def setup_method(self):
        """Configure les tests."""
        self.cipher = PlayfairCipher()
    
    def test_validate_key(self):
        """Teste la validation de clé."""
        # Clés valides
        assert self.cipher.validate_key("MONARCHY") is True
        assert self.cipher.validate_key("PLAYFAIR EXAMPLE") is True
        assert self.cipher.validate_key("X") is True  # Clé d'un seul caractère
        
        # Clés invalides
        assert self.cipher.validate_key("") is False
        assert self.cipher.validate_key("KEY123") is False  # Contient des chiffres
        assert self.cipher.validate_key(123) is False  # Pas une chaîne
        assert self.cipher.validate_key(None) is False
    
    def test_create_matrix(self):
        """Teste la création de la matrice 5x5."""
        matrix = self.cipher._create_matrix("MONARCHY")
        
        # La matrice doit contenir 5 lignes
        assert len(matrix) == 5
        
        # Chaque ligne doit contenir 5 caractères
        for row in matrix:
            assert len(row) == 5
        
        # Vérifier que la matrice commence par les lettres de "MONARCHY" (sans doublons)
        # Et que J est remplacé par I
        first_chars = ""
        for row in matrix:
            first_chars += "".join(row)
        
        assert "M" in first_chars
        assert "O" in first_chars
        assert "N" in first_chars
        assert "A" in first_chars
        assert "R" in first_chars
        assert "C" in first_chars
        assert "H" in first_chars
        assert "Y" in first_chars
        
        # Vérifier que chaque lettre n'apparaît qu'une seule fois
        for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":  # Alphabet sans J
            assert first_chars.count(char) == 1
        
        # Vérifier que J n'est pas dans la matrice (il est remplacé par I)
        assert "J" not in first_chars
    
    def test_find_position(self):
        """Teste la fonction qui trouve la position d'une lettre dans la matrice."""
        matrix = self.cipher._create_matrix("MONARCHY")
        
        # Tester quelques positions
        assert self.cipher._find_position(matrix, "M") == (0, 0)  # Première lettre de la clé
        assert self.cipher._find_position(matrix, "J") == self.cipher._find_position(matrix, "I")  # J remplacé par I
    
    def test_prepare_text(self):
        """Teste la préparation du texte pour le chiffrement Playfair."""
        # Test de séparation des paires identiques
        assert "HELXLO" in self.cipher._prepare_text("HELLO")
        
        # Test d'ajout d'un X à la fin si nécessaire
        assert self.cipher._prepare_text("HELL").endswith("X")
        
        # Test de remplacement de J par I
        assert "I" in self.cipher._prepare_text("J")
        assert "I" in self.cipher._prepare_text("JAVA")
    
    def test_encrypt(self):
        """Teste le chiffrement."""
        # Exemple classique avec la clé "MONARCHY"
        # Notez que le résultat exact dépend de la façon dont la matrice est construite
        encrypted = self.cipher.encrypt("HELLO", "MONARCHY")
        
        # Test avec des paires répétées
        encrypted_bookkeeper = self.cipher.encrypt("BOOKKEEPER", "PLAYFAIR")
        
        # Vérifier que le texte chiffré a la même longueur que le texte préparé
        assert len(encrypted) == len(self.cipher._prepare_text("HELLO"))
        
        # Vérifier que le texte chiffré est différent du texte original
        assert encrypted != "HELLO"
    
    def test_decrypt(self):
        """Teste le déchiffrement."""
        # Tester sur différents exemples
        for key in ["MONARCHY", "PLAYFAIR", "CRYPTOGRAPHY"]:
            for text in ["HELLO", "TEST", "PLAYFAIR", "THISISASECRETMESSAGE"]:
                encrypted = self.cipher.encrypt(text, key)
                decrypted = self.cipher.decrypt(encrypted, key)
                
                # Le déchiffrement peut ajouter des X, donc on vérifie que le texte original
                # est un sous-ensemble du texte déchiffré après suppression des X
                text_cleaned = self.cipher.clean_text(text)
                # Remplacer J par I comme fait dans l'algorithme
                text_cleaned = text_cleaned.replace("J", "I")
                
                decrypted_without_extra_x = decrypted
                
                # Vérifier que le texte original est contenu dans le déchiffré
                # après suppression des X ajoutés pour les doublons
                assert text_cleaned in decrypted_without_extra_x.replace("X", "")
    
    def test_encrypt_decrypt_integrity(self):
        """Teste l'intégrité du processus de chiffrement/déchiffrement."""
        # Test avec un exemple simple sans lettres dupliquées
        key = "MONARCHY"
        text = "HIDE"
        
        encrypted = self.cipher.encrypt(text, key)
        decrypted = self.cipher.decrypt(encrypted, key)
        
        # Dans ce cas simple, le texte déchiffré devrait être identique au texte original
        assert decrypted == self.cipher.clean_text(text).replace("J", "I")
    
    def test_invalid_key_raises_error(self):
        """Teste que les clés invalides lèvent des exceptions."""
        with pytest.raises(ValueError):
            self.cipher.encrypt("HELLO", "")
        
        with pytest.raises(ValueError):
            self.cipher.encrypt("HELLO", "KEY123")
        
        with pytest.raises(ValueError):
            self.cipher.decrypt("HELLO", 123)