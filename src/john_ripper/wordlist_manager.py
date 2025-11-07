"""
Gestionnaire de wordlists pour John the Ripper.

Crée et gère des listes de mots de passe pour les attaques par dictionnaire.
"""

import os
from typing import List, Optional, Set
from pathlib import Path


class WordlistManager:
    """
    Gère les wordlists pour les attaques par dictionnaire.

    Fournit des wordlists communes et permet d'en créer de personnalisées.
    """

    # Top 100 mots de passe les plus courants (basé sur des études réelles)
    COMMON_PASSWORDS = [
        "123456", "password", "123456789", "12345678", "12345",
        "1234567", "password1", "123123", "1234567890", "000000",
        "abc123", "111111", "qwerty", "1q2w3e4r", "admin",
        "letmein", "welcome", "monkey", "dragon", "master",
        "sunshine", "princess", "football", "shadow", "superman",
        "iloveyou", "michael", "trustno1", "batman", "jordan",
        "jennifer", "hunter", "test", "charlie", "thomas",
        "robert", "tigger", "daniel", "michelle", "jessica",
        "pepper", "hello", "freedom", "nicole", "ginger",
        "secret", "chocolate", "ranger", "maggie", "summer",
        "buster", "soccer", "jordan23", "ashley", "matrix",
        "madison", "bailey", "killer", "access", "cookie",
        "computer", "internet", "starwars", "scooter", "ranger",
        "banana", "junior", "555555", "lovely", "passw0rd",
        "qwerty123", "Password1", "password123", "p@ssw0rd", "admin123",
        "root", "toor", "test123", "letmein1", "welcome1",
        "azerty", "qwertyuiop", "1q2w3e", "zaq12wsx", "123qwe",
        "123abc", "password!", "Password", "Admin", "User",
        "guest", "demo", "default", "changeme", "temp",
        "temp123", "pass", "pass123", "pass1234", "admin1"
    ]

    # Mots de passe français courants
    FRENCH_PASSWORDS = [
        "motdepasse", "azerty", "azerty123", "soleil", "bonjour",
        "marseille", "chocolat", "doudou", "loulou", "chouchou",
        "nicolas", "thomas", "alexis", "marine", "camille",
        "france", "paris", "lyon", "marseille13", "jetaime",
        "amour", "famille", "liberte", "secret123", "password123"
    ]

    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialise le gestionnaire de wordlists.

        Args:
            output_dir (str, optional): Répertoire pour sauvegarder les wordlists
        """
        self.output_dir = output_dir or os.getcwd()
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def get_common_passwords(self, include_french: bool = True) -> List[str]:
        """
        Retourne la liste des mots de passe courants.

        Args:
            include_french (bool): Inclure les mots de passe français

        Returns:
            list: Liste de mots de passe
        """
        passwords = self.COMMON_PASSWORDS.copy()

        if include_french:
            passwords.extend(self.FRENCH_PASSWORDS)

        return passwords

    def create_wordlist(
        self,
        passwords: List[str],
        filename: str = 'custom_wordlist.txt',
        deduplicate: bool = True
    ) -> str:
        """
        Crée une wordlist personnalisée.

        Args:
            passwords (list): Liste de mots de passe
            filename (str): Nom du fichier
            deduplicate (bool): Supprimer les doublons

        Returns:
            str: Chemin vers le fichier créé
        """
        filepath = os.path.join(self.output_dir, filename)

        if deduplicate:
            passwords = list(set(passwords))

        with open(filepath, 'w', encoding='utf-8') as f:
            for password in passwords:
                f.write(f"{password}\n")

        return filepath

    def create_common_wordlist(self, filename: str = 'common_passwords.txt') -> str:
        """
        Crée une wordlist avec les mots de passe courants.

        Args:
            filename (str): Nom du fichier

        Returns:
            str: Chemin vers le fichier créé
        """
        passwords = self.get_common_passwords(include_french=True)
        return self.create_wordlist(passwords, filename)

    def create_numeric_wordlist(
        self,
        min_length: int = 4,
        max_length: int = 8,
        filename: str = 'numeric_wordlist.txt'
    ) -> str:
        """
        Crée une wordlist de combinaisons numériques.

        ATTENTION: Peut générer des fichiers très volumineux!

        Args:
            min_length (int): Longueur minimale
            max_length (int): Longueur maximale
            filename (str): Nom du fichier

        Returns:
            str: Chemin vers le fichier créé
        """
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w') as f:
            # Pour éviter les fichiers trop gros, limiter à max 6 caractères
            actual_max = min(max_length, 6)

            for length in range(min_length, actual_max + 1):
                # Générer tous les nombres de cette longueur
                start = 10 ** (length - 1) if length > 1 else 0
                end = 10 ** length

                for num in range(start, end):
                    f.write(f"{num:0{length}d}\n")

        return filepath

    def create_pattern_wordlist(
        self,
        base_words: List[str],
        add_numbers: bool = True,
        add_symbols: bool = False,
        filename: str = 'pattern_wordlist.txt'
    ) -> str:
        """
        Crée une wordlist avec des variations sur des mots de base.

        Ajoute des variations courantes: chiffres, casse, symboles.

        Args:
            base_words (list): Mots de base
            add_numbers (bool): Ajouter des chiffres (123, 2023, etc.)
            add_symbols (bool): Ajouter des symboles (!, @, etc.)
            filename (str): Nom du fichier

        Returns:
            str: Chemin vers le fichier créé
        """
        filepath = os.path.join(self.output_dir, filename)
        variations = set()

        for word in base_words:
            # Mot original
            variations.add(word)

            # Variations de casse
            variations.add(word.lower())
            variations.add(word.upper())
            variations.add(word.capitalize())

            # Ajout de chiffres
            if add_numbers:
                for num in ['1', '12', '123', '1234', '2023', '2024', '2025', '!']:
                    variations.add(word + num)
                    variations.add(word.capitalize() + num)

            # Ajout de symboles
            if add_symbols:
                for symbol in ['!', '@', '#', '$', '!@#']:
                    variations.add(word + symbol)
                    variations.add(word.capitalize() + symbol)

            # Leet speak basique
            leet = word.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0')
            variations.add(leet)

        # Écrire dans le fichier
        with open(filepath, 'w', encoding='utf-8') as f:
            for password in sorted(variations):
                f.write(f"{password}\n")

        return filepath

    def combine_wordlists(
        self,
        wordlist_files: List[str],
        output_filename: str = 'combined_wordlist.txt',
        deduplicate: bool = True
    ) -> str:
        """
        Combine plusieurs wordlists en une seule.

        Args:
            wordlist_files (list): Liste des chemins vers les wordlists
            output_filename (str): Nom du fichier de sortie
            deduplicate (bool): Supprimer les doublons

        Returns:
            str: Chemin vers le fichier combiné
        """
        passwords = []

        for filepath in wordlist_files:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords.extend(line.strip() for line in f if line.strip())

        if deduplicate:
            passwords = list(set(passwords))

        output_path = os.path.join(self.output_dir, output_filename)

        with open(output_path, 'w', encoding='utf-8') as f:
            for password in passwords:
                f.write(f"{password}\n")

        return output_path

    def get_wordlist_stats(self, filepath: str) -> dict:
        """
        Analyse une wordlist et retourne des statistiques.

        Args:
            filepath (str): Chemin vers la wordlist

        Returns:
            dict: Statistiques sur la wordlist
        """
        if not os.path.exists(filepath):
            return {'error': 'Fichier non trouvé'}

        stats = {
            'total_lines': 0,
            'unique_passwords': 0,
            'min_length': float('inf'),
            'max_length': 0,
            'avg_length': 0,
            'numeric_only': 0,
            'alpha_only': 0,
            'alphanumeric': 0,
            'with_symbols': 0
        }

        passwords = set()
        total_length = 0

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if not password:
                    continue

                stats['total_lines'] += 1
                passwords.add(password)

                length = len(password)
                total_length += length
                stats['min_length'] = min(stats['min_length'], length)
                stats['max_length'] = max(stats['max_length'], length)

                # Catégoriser
                if password.isdigit():
                    stats['numeric_only'] += 1
                elif password.isalpha():
                    stats['alpha_only'] += 1
                elif password.isalnum():
                    stats['alphanumeric'] += 1
                else:
                    stats['with_symbols'] += 1

        stats['unique_passwords'] = len(passwords)
        stats['avg_length'] = total_length / stats['total_lines'] if stats['total_lines'] > 0 else 0

        return stats

    def display_wordlist_info(self, filepath: str) -> str:
        """
        Affiche des informations formatées sur une wordlist.

        Args:
            filepath (str): Chemin vers la wordlist

        Returns:
            str: Informations formatées
        """
        stats = self.get_wordlist_stats(filepath)

        if 'error' in stats:
            return f"Erreur: {stats['error']}"

        output = []
        output.append("="*70)
        output.append(f"WORDLIST: {os.path.basename(filepath)}")
        output.append("="*70)
        output.append(f"Chemin: {filepath}")
        output.append(f"Taille: {os.path.getsize(filepath) / 1024:.2f} KB")
        output.append("")
        output.append("STATISTIQUES:")
        output.append(f"  Nombre total de lignes:     {stats['total_lines']:,}")
        output.append(f"  Mots de passe uniques:      {stats['unique_passwords']:,}")
        output.append(f"  Longueur minimale:          {stats['min_length']}")
        output.append(f"  Longueur maximale:          {stats['max_length']}")
        output.append(f"  Longueur moyenne:           {stats['avg_length']:.1f}")
        output.append("")
        output.append("CATÉGORIES:")
        output.append(f"  Numérique seulement:        {stats['numeric_only']:,}")
        output.append(f"  Alphabétique seulement:     {stats['alpha_only']:,}")
        output.append(f"  Alphanumérique:             {stats['alphanumeric']:,}")
        output.append(f"  Avec symboles:              {stats['with_symbols']:,}")
        output.append("="*70)

        # Afficher quelques exemples
        output.append("")
        output.append("EXEMPLES (10 premiers):")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= 10:
                    break
                output.append(f"  {i+1}. {line.strip()}")

        output.append("="*70)

        return '\n'.join(output)
