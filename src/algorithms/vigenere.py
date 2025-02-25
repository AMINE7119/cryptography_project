from .base import CipherAlgorithm

class VigenereCipher(CipherAlgorithm):
    """
    Implémentation du chiffrement de Vigenère.
    
    Le chiffrement de Vigenère est une méthode de chiffrement par substitution
    utilisant une série de chiffrements de César différents basés sur les lettres d'un mot-clé.
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Vigenère"
        
    def validate_key(self, key: str) -> bool:
        """
        Valide que la clé est une chaîne non vide contenant uniquement des lettres.
        
        Args:
            key (str): La clé à valider
            
        Returns:
            bool: True si la clé est valide, False sinon
        """
        if not isinstance(key, str) or not key:
            return False
        return all(c.isalpha() for c in key)
            
    def encrypt(self, text: str, key: str) -> str:
        """
        Chiffre le texte en utilisant l'algorithme de Vigenère.
        
        Args:
            text (str): Le texte à chiffrer
            key (str): La clé de chiffrement (mot)
            
        Returns:
            str: Le texte chiffré
        """
        if not self.validate_key(key):
            raise ValueError("La clé doit être un mot non vide contenant uniquement des lettres")
            
        text = self.clean_text(text)
        key = self.clean_text(key)
        result = ""
        
        for i, char in enumerate(text):
            if char.isalpha():
                # Calcul l'indice de la lettre de la clé correspondante
                key_char = key[i % len(key)]
                key_shift = ord(key_char) - ord('A')
                
                # Chiffrement: (lettre_texte + lettre_clé) % 26
                char_code = ord(char) - ord('A')
                encrypted_code = (char_code + key_shift) % 26
                result += chr(encrypted_code + ord('A'))
            else:
                result += char
                
        return result
    
    def decrypt(self, text: str, key: str) -> str:
        """
        Déchiffre le texte chiffré avec l'algorithme de Vigenère.
        
        Args:
            text (str): Le texte à déchiffrer
            key (str): La clé de chiffrement utilisée (mot)
            
        Returns:
            str: Le texte déchiffré
        """
        if not self.validate_key(key):
            raise ValueError("La clé doit être un mot non vide contenant uniquement des lettres")
            
        text = self.clean_text(text)
        key = self.clean_text(key)
        result = ""
        
        for i, char in enumerate(text):
            if char.isalpha():
                # Calcul l'indice de la lettre de la clé correspondante
                key_char = key[i % len(key)]
                key_shift = ord(key_char) - ord('A')
                
                # Déchiffrement: (lettre_chiffrée - lettre_clé + 26) % 26
                char_code = ord(char) - ord('A')
                decrypted_code = (char_code - key_shift + 26) % 26
                result += chr(decrypted_code + ord('A'))
            else:
                result += char
                
        return result