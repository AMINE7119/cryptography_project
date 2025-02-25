class InputValidator:
    """Classe pour valider les entrées utilisateur."""
    
    @staticmethod
    def validate_text(text: str) -> bool:
        """
        Vérifie si le texte fourni est valide.
        
        Args:
            text (str): Le texte à valider
            
        Returns:
            bool: True si le texte est valide, False sinon
        """
        if not isinstance(text, str):
            return False
        if not text.strip():
            return False
        return True
    
    @staticmethod
    def validate_caesar_key(key: str) -> bool:
        """
        Vérifie si la clé fournie est valide pour le chiffrement de César.
        
        Args:
            key (str): La clé à valider
            
        Returns:
            bool: True si la clé est valide, False sinon
        """
        try:
            key_int = int(key)
            return 0 <= key_int <= 25
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_vigenere_key(key: str) -> bool:
        """
        Vérifie si la clé fournie est valide pour le chiffrement de Vigenère.
        
        Args:
            key (str): La clé à valider
            
        Returns:
            bool: True si la clé est valide, False sinon
        """
        if not isinstance(key, str) or not key.strip():
            return False
        return all(c.isalpha() or c.isspace() for c in key)
    
    @staticmethod
    def validate_playfair_key(key: str) -> bool:
        """
        Vérifie si la clé fournie est valide pour le chiffrement de Playfair.
        
        Args:
            key (str): La clé à valider
            
        Returns:
            bool: True si la clé est valide, False sinon
        """
        if not isinstance(key, str) or not key.strip():
            return False
        return all(c.isalpha() or c.isspace() for c in key)