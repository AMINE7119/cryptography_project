from .base import CipherAlgorithm
import re

class PlayfairCipher(CipherAlgorithm):
    """
    Implémentation du chiffrement de Playfair.
    
    Le chiffrement de Playfair utilise une matrice 5x5 de lettres construite à partir
    d'un mot-clé, puis applique des règles spécifiques pour chiffrer des paires de lettres.
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Playfair"
        
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
        return all(c.isalpha() or c.isspace() for c in key)
    
    def _create_matrix(self, key: str) -> list:
        """
        Crée la matrice 5x5 à partir de la clé.
        
        Args:
            key (str): La clé pour générer la matrice
            
        Returns:
            list: Une matrice 5x5 de lettres
        """
        # Remplacer J par I dans la clé et le texte
        key = self.clean_text(key).replace('J', 'I')
        
        # Créer un alphabet sans J
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        
        # Générer la matrice à partir de la clé
        matrix = []
        matrix_flat = ""
        
        # D'abord ajouter les lettres de la clé (sans doublons)
        for char in key:
            if char.isalpha() and char not in matrix_flat:
                matrix_flat += char
        
        # Ensuite ajouter le reste de l'alphabet
        for char in alphabet:
            if char not in matrix_flat:
                matrix_flat += char
        
        # Convertir en matrice 5x5
        for i in range(0, 25, 5):
            matrix.append(list(matrix_flat[i:i+5]))
        
        return matrix
    
    def _find_position(self, matrix: list, char: str) -> tuple:
        """
        Trouve la position d'un caractère dans la matrice.
        
        Args:
            matrix (list): La matrice 5x5
            char (str): Le caractère à trouver
            
        Returns:
            tuple: Coordonnées (row, col) du caractère
        """
        char = char.upper()
        # Remplacer J par I pour le traitement
        if char == 'J':
            char = 'I'
            
        for row in range(5):
            for col in range(5):
                if matrix[row][col] == char:
                    return (row, col)
        return (-1, -1)  # Caractère non trouvé
    
    def _prepare_text(self, text: str) -> str:
        """
        Prépare le texte pour le chiffrement Playfair.
        
        Args:
            text (str): Le texte à préparer
            
        Returns:
            str: Le texte préparé
        """
        text = self.clean_text(text).replace('J', 'I')
        
        # Séparer les doublons avec un 'X'
        result = ""
        i = 0
        
        while i < len(text):
            if i+1 < len(text):
                if text[i] == text[i+1]:
                    result += text[i] + 'X'
                    i += 1
                else:
                    result += text[i] + text[i+1]
                    i += 2
            else:
                result += text[i] + 'X'
                i += 1
        
        return result
    
    def encrypt(self, text: str, key: str) -> str:
        """
        Chiffre le texte en utilisant l'algorithme de Playfair.
        
        Args:
            text (str): Le texte à chiffrer
            key (str): La clé pour générer la matrice
            
        Returns:
            str: Le texte chiffré
        """
        if not self.validate_key(key):
            raise ValueError("La clé doit contenir uniquement des lettres")
        
        matrix = self._create_matrix(key)
        text = self._prepare_text(text)
        result = ""
        
        # Traitement par paires de lettres
        for i in range(0, len(text), 2):
            char1 = text[i]
            char2 = text[i+1] if i+1 < len(text) else 'X'
            
            row1, col1 = self._find_position(matrix, char1)
            row2, col2 = self._find_position(matrix, char2)
            
            # Règle 1: Même ligne, décalage à droite
            if row1 == row2:
                result += matrix[row1][(col1+1)%5] + matrix[row2][(col2+1)%5]
            # Règle 2: Même colonne, décalage en bas
            elif col1 == col2:
                result += matrix[(row1+1)%5][col1] + matrix[(row2+1)%5][col2]
            # Règle 3: Former un rectangle
            else:
                result += matrix[row1][col2] + matrix[row2][col1]
        
        return result
    
    def decrypt(self, text: str, key: str) -> str:
        """
        Déchiffre le texte chiffré avec l'algorithme de Playfair.
        
        Args:
            text (str): Le texte à déchiffrer
            key (str): La clé utilisée pour générer la matrice
            
        Returns:
            str: Le texte déchiffré
        """
        if not self.validate_key(key):
            raise ValueError("La clé doit contenir uniquement des lettres")
        
        matrix = self._create_matrix(key)
        text = self.clean_text(text)
        result = ""
        
        # Traitement par paires de lettres
        for i in range(0, len(text), 2):
            char1 = text[i]
            char2 = text[i+1] if i+1 < len(text) else 'X'
            
            row1, col1 = self._find_position(matrix, char1)
            row2, col2 = self._find_position(matrix, char2)
            
            # Règle 1: Même ligne, décalage à gauche
            if row1 == row2:
                result += matrix[row1][(col1-1)%5] + matrix[row2][(col2-1)%5]
            # Règle 2: Même colonne, décalage en haut
            elif col1 == col2:
                result += matrix[(row1-1)%5][col1] + matrix[(row2-1)%5][col2]
            # Règle 3: Former un rectangle
            else:
                result += matrix[row1][col2] + matrix[row2][col1]
        
        # Ne pas supprimer automatiquement les X d'espacement pour éviter les erreurs
        return result