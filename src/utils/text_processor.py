import re

class TextProcessor:
    """Classe pour le traitement de texte avant et après chiffrement."""
    
    @staticmethod
    def clean_for_encryption(text: str, preserve_spaces: bool = False) -> str:
        """
        Nettoie le texte pour le chiffrement.
        
        Args:
            text (str): Le texte à nettoyer
            preserve_spaces (bool): Si True, conserve les espaces
            
        Returns:
            str: Le texte nettoyé
        """
        # Convertir en majuscules
        text = text.upper()
        
        if preserve_spaces:
            # Supprimer tous les caractères sauf les lettres et les espaces
            text = re.sub(r'[^A-Z\s]', '', text)
        else:
            # Supprimer tous les caractères sauf les lettres
            text = re.sub(r'[^A-Z]', '', text)
            
        return text
    
    @staticmethod
    def format_output(text: str, block_size: int = 5) -> str:
        """
        Formate le texte chiffré en blocs pour une meilleure lisibilité.
        
        Args:
            text (str): Le texte à formater
            block_size (int): La taille des blocs
            
        Returns:
            str: Le texte formaté
        """
        # Supprime les espaces et forme des blocs
        text = text.replace(" ", "")
        return ' '.join([text[i:i+block_size] for i in range(0, len(text), block_size)])
    
    @staticmethod
    def prepare_for_playfair(text: str) -> str:
        """
        Prépare le texte pour le chiffrement Playfair.
        
        Args:
            text (str): Le texte à préparer
            
        Returns:
            str: Le texte préparé
        """
        # Nettoyer le texte
        text = TextProcessor.clean_for_encryption(text)
        
        # Remplacer J par I
        text = text.replace('J', 'I')
        
        # Séparer les doublons avec X
        result = ""
        i = 0
        
        while i < len(text):
            if i + 1 < len(text):
                if text[i] == text[i + 1]:
                    result += text[i] + 'X'
                    i += 1
                else:
                    result += text[i] + text[i + 1]
                    i += 2
            else:
                result += text[i] + 'X'
                i += 1
        
        return result
    
    @staticmethod
    def restore_playfair_text(text: str) -> str:
        """
        Restaure le texte après déchiffrement Playfair (supprime les X d'espacement).
        
        Args:
            text (str): Le texte déchiffré à restaurer
            
        Returns:
            str: Le texte restauré
        """
        # Cette fonction est approximative car il est difficile de distinguer
        # les X légitimes des X d'espacement
        
        # Supprimer les X à la fin
        if text.endswith('X'):
            text = text[:-1]
            
        # Supprimer les X entre doublons consécutifs
        # Note: Cette approche n'est pas parfaite et peut supprimer des X légitimes
        i = 1
        while i < len(text) - 1:
            if text[i] == 'X' and text[i - 1] == text[i + 1]:
                text = text[:i] + text[i + 1:]
            else:
                i += 1
        
        return text