import random
import string

class KeyGenerator:
    """Classe pour générer des clés de chiffrement."""
    
    @staticmethod
    def generate_caesar_key() -> int:
        """
        Génère une clé aléatoire pour le chiffrement de César.
        
        Returns:
            int: Une clé entre 1 et 25
        """
        return random.randint(1, 25)
    
    @staticmethod
    def generate_vigenere_key(length: int = 8) -> str:
        """
        Génère une clé aléatoire pour le chiffrement de Vigenère.
        
        Args:
            length (int): Longueur de la clé
            
        Returns:
            str: Une clé aléatoire composée de lettres majuscules
        """
        return ''.join(random.choice(string.ascii_uppercase) for _ in range(length))
    
    @staticmethod
    def generate_playfair_key(length: int = 10) -> str:
        """
        Génère une clé aléatoire pour le chiffrement de Playfair.
        
        Args:
            length (int): Longueur de la clé
            
        Returns:
            str: Une clé aléatoire composée de lettres majuscules
        """
        # Éviter les doublons dans la clé
        key_chars = []
        alphabet = string.ascii_uppercase.replace('J', '')  # Exclure J
        
        while len(key_chars) < length:
            char = random.choice(alphabet)
            if char not in key_chars:
                key_chars.append(char)
                
        return ''.join(key_chars)