"""
Module principal qui coordonne les opérations de chiffrement et déchiffrement.
"""

from algorithms.caesar import CaesarCipher
from algorithms.vigenere import VigenereCipher
from algorithms.playfair import PlayfairCipher
from utils.text_processor import TextProcessor
from core.config import ALGORITHMS


class CryptoEngine:
    """
    Moteur principal de cryptographie qui gère les algorithmes disponibles
    et coordonne les opérations de chiffrement/déchiffrement.
    """
    
    def __init__(self):
        """Initialise le moteur de cryptographie avec les algorithmes disponibles."""
        self.algorithms = {
            "César": CaesarCipher(),
            "Vigenère": VigenereCipher(),
            "Playfair": PlayfairCipher()
        }
        self.text_processor = TextProcessor()
        
    def get_available_algorithms(self):
        """
        Retourne la liste des noms d'algorithmes disponibles.
        
        Returns:
            list: Liste des noms d'algorithmes
        """
        return list(self.algorithms.keys())
    
    def get_algorithm_info(self, name):
        """
        Retourne les informations sur un algorithme spécifique.
        
        Args:
            name (str): Nom de l'algorithme
            
        Returns:
            dict: Informations sur l'algorithme
        """
        if name in ALGORITHMS:
            return ALGORITHMS[name]
        return None
    
    def encrypt(self, text, algorithm_name, key):
        """
        Chiffre le texte avec l'algorithme spécifié et la clé fournie.
        
        Args:
            text (str): Le texte à chiffrer
            algorithm_name (str): Le nom de l'algorithme à utiliser
            key: La clé de chiffrement
            
        Returns:
            str: Le texte chiffré
            
        Raises:
            ValueError: Si l'algorithme n'existe pas ou si la clé est invalide
        """
        if algorithm_name not in self.algorithms:
            raise ValueError(f"Algorithme '{algorithm_name}' non disponible")
        
        algorithm = self.algorithms[algorithm_name]
        
        if not algorithm.validate_key(key):
            raise ValueError(f"Clé invalide pour l'algorithme {algorithm_name}")
        
        # Prétraitement du texte si nécessaire
        preprocessed_text = text
        
        # Chiffrement
        encrypted_text = algorithm.encrypt(preprocessed_text, key)
        
        # Post-traitement (formatage) du texte chiffré
        formatted_text = self.text_processor.format_output(encrypted_text)
        
        return formatted_text
    
    def decrypt(self, text, algorithm_name, key):
        """
        Déchiffre le texte avec l'algorithme spécifié et la clé fournie.
        
        Args:
            text (str): Le texte à déchiffrer
            algorithm_name (str): Le nom de l'algorithme à utiliser
            key: La clé de déchiffrement
            
        Returns:
            str: Le texte déchiffré
            
        Raises:
            ValueError: Si l'algorithme n'existe pas ou si la clé est invalide
        """
        if algorithm_name not in self.algorithms:
            raise ValueError(f"Algorithme '{algorithm_name}' non disponible")
        
        algorithm = self.algorithms[algorithm_name]
        
        if not algorithm.validate_key(key):
            raise ValueError(f"Clé invalide pour l'algorithme {algorithm_name}")
        
        # Prétraitement du texte (suppression des espaces ajoutés pour le formatage)
        preprocessed_text = text.replace(" ", "")
        
        # Déchiffrement
        decrypted_text = algorithm.decrypt(preprocessed_text, key)
        
        return decrypted_text