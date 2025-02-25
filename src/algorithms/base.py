from abc import ABC, abstractmethod
from typing import Any

class CipherAlgorithm(ABC):
    """Classe de base abstraite pour tous les algorithmes de chiffrement."""
    
    def __init__(self):
        self.name = self.__class__.__name__
    
    @abstractmethod
    def encrypt(self, text: str, key: Any) -> str:
        """
        Chiffre le texte donné avec la clé spécifiée.
        
        Args:
            text (str): Le texte à chiffrer
            key (Any): La clé de chiffrement
            
        Returns:
            str: Le texte chiffré
        """
        pass
    
    @abstractmethod
    def decrypt(self, text: str, key: Any) -> str:
        """
        Déchiffre le texte donné avec la clé spécifiée.
        
        Args:
            text (str): Le texte à déchiffrer
            key (Any): La clé de déchiffrement
            
        Returns:
            str: Le texte déchiffré
        """
        pass
    
    @abstractmethod
    def validate_key(self, key: Any) -> bool:
        """
        Valide la clé fournie pour l'algorithme.
        
        Args:
            key (Any): La clé à valider
            
        Returns:
            bool: True si la clé est valide, False sinon
        """
        pass
    
    def clean_text(self, text: str) -> str:
        """
        Nettoie le texte en entrée (supprime les espaces et la ponctuation si nécessaire).
        
        Args:
            text (str): Le texte à nettoyer
            
        Returns:
            str: Le texte nettoyé
        """
        return text.upper().replace(" ", "")