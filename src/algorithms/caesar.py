from .base import CipherAlgorithm

class CaesarCipher(CipherAlgorithm):
    """
    Implémentation du chiffrement de César.
    
    Le chiffrement de César est une méthode de substitution simple où chaque lettre
    du texte en clair est remplacée par une lettre située à un nombre fixe de positions
    plus loin dans l'alphabet.
    """
    
    def __init__(self):
        super().__init__()
        self.name = "César"
        
    def validate_key(self, key: int) -> bool:
        """
        Valide que la clé est un entier entre 0 et 25.
        
        Args:
            key (int): La clé à valider
            
        Returns:
            bool: True si la clé est valide, False sinon
        """
        try:
            key = int(key)
            return 0 <= key <= 25
        except (ValueError, TypeError):
            return False
            
    def encrypt(self, text: str, key: int) -> str:
        """
        Chiffre le texte en utilisant l'algorithme de César.
        
        Args:
            text (str): Le texte à chiffrer
            key (int): Le décalage à appliquer (0-25)
            
        Returns:
            str: Le texte chiffré
        """
        if not self.validate_key(key):
            raise ValueError("La clé doit être un entier entre 0 et 25")
            
        key = int(key)
        result = ""
        text = self.clean_text(text)
        
        for char in text:
            if char.isalpha():
                # Conversion de la lettre en code ASCII, application du décalage
                ascii_offset = ord('A')
                # Formule : (position_lettre + décalage) % 26
                shifted = (ord(char) - ascii_offset + key) % 26
                result += chr(shifted + ascii_offset)
            else:
                result += char
                
        return result
    
    def decrypt(self, text: str, key: int) -> str:
        """
        Déchiffre le texte chiffré avec l'algorithme de César.
        
        Args:
            text (str): Le texte à déchiffrer
            key (int): Le décalage appliqué (0-25)
            
        Returns:
            str: Le texte déchiffré
        """
        if not self.validate_key(key):
            raise ValueError("La clé doit être un entier entre 0 et 25")
            
        # Pour déchiffrer, on utilise le décalage inverse (26 - key)
        return self.encrypt(text, (26 - int(key)) % 26)