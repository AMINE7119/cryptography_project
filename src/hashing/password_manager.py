"""
Simulateur de base de données de mots de passe pour démonstration éducative.
"""

import json
import os
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from .hash_algorithms import HashEngine
from .salt_pepper import SaltGenerator


class PasswordDatabase:
    """
    Simule une base de données de mots de passe sécurisée.

    Démontre les bonnes pratiques de stockage de mots de passe.
    """

    def __init__(self, pepper: Optional[str] = None):
        """
        Initialise la base de données.

        Args:
            pepper (str, optional): Pepper de l'application (secret)
        """
        self.users = {}
        self.hash_engine = HashEngine()
        self.salt_gen = SaltGenerator()
        self.pepper = pepper or self.salt_gen.generate_pepper()
        self.failed_attempts = {}  # Pour tracking des tentatives échouées

    def add_user(self, username: str, password: str,
                 method: str = 'bcrypt') -> bool:
        """
        Ajoute un utilisateur avec son mot de passe haché.

        Args:
            username (str): Nom d'utilisateur
            password (str): Mot de passe en clair
            method (str): Méthode de hachage ('bcrypt', 'pbkdf2', 'sha256_salt')

        Returns:
            bool: True si ajouté avec succès
        """
        if username in self.users:
            return False

        if method == 'bcrypt':
            # bcrypt gère le salt automatiquement
            password_hash = self.hash_engine.hash_bcrypt(password)
            self.users[username] = {
                'method': 'bcrypt',
                'hash': password_hash,
                'salt': None,  # Inclus dans le hash
                'created_at': datetime.now().isoformat()
            }

        elif method == 'pbkdf2':
            salt = self.salt_gen.generate_salt()
            password_hash = self.salt_gen.pbkdf2_hash(password, salt, iterations=100000)
            self.users[username] = {
                'method': 'pbkdf2',
                'hash': password_hash,
                'salt': salt,
                'created_at': datetime.now().isoformat()
            }

        elif method == 'sha256_salt':
            salt = self.salt_gen.generate_salt()
            password_hash = self.salt_gen.hash_with_salt_and_pepper(
                password, salt, self.pepper, algorithm='sha256'
            )
            self.users[username] = {
                'method': 'sha256_salt',
                'hash': password_hash,
                'salt': salt,
                'created_at': datetime.now().isoformat()
            }

        elif method == 'insecure_md5':
            # Pour démonstration de ce qu'il NE FAUT PAS faire
            password_hash = self.hash_engine.hash_md5(password)
            self.users[username] = {
                'method': 'insecure_md5',
                'hash': password_hash,
                'salt': None,
                'created_at': datetime.now().isoformat(),
                'warning': 'INSECURE - For demonstration only!'
            }

        else:
            raise ValueError(f"Méthode non supportée: {method}")

        return True

    def verify_password(self, username: str, password: str) -> bool:
        """
        Vérifie le mot de passe d'un utilisateur.

        Args:
            username (str): Nom d'utilisateur
            password (str): Mot de passe à vérifier

        Returns:
            bool: True si le mot de passe est correct
        """
        if username not in self.users:
            return False

        user_data = self.users[username]
        method = user_data['method']

        try:
            if method == 'bcrypt':
                return self.hash_engine.verify_bcrypt(password, user_data['hash'])

            elif method == 'pbkdf2':
                password_hash = self.salt_gen.pbkdf2_hash(
                    password, user_data['salt'], iterations=100000
                )
                return password_hash == user_data['hash']

            elif method == 'sha256_salt':
                password_hash = self.salt_gen.hash_with_salt_and_pepper(
                    password, user_data['salt'], self.pepper, algorithm='sha256'
                )
                return password_hash == user_data['hash']

            elif method == 'insecure_md5':
                password_hash = self.hash_engine.hash_md5(password)
                return password_hash == user_data['hash']

            return False

        except Exception as e:
            print(f"Erreur de vérification: {e}")
            return False

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Tente une connexion utilisateur avec tracking des tentatives.

        Args:
            username (str): Nom d'utilisateur
            password (str): Mot de passe

        Returns:
            tuple: (succès, message)
        """
        # Vérifier le verrouillage
        if username in self.failed_attempts:
            if self.failed_attempts[username] >= 5:
                return False, "Compte verrouillé après 5 tentatives échouées"

        # Vérifier le mot de passe
        if self.verify_password(username, password):
            # Réinitialiser les tentatives échouées
            self.failed_attempts[username] = 0
            return True, "Connexion réussie"
        else:
            # Incrémenter les tentatives échouées
            self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
            remaining = 5 - self.failed_attempts[username]
            return False, f"Mot de passe incorrect ({remaining} tentatives restantes)"

    def get_user_info(self, username: str) -> Optional[Dict]:
        """
        Retourne les informations (publiques) d'un utilisateur.

        Args:
            username (str): Nom d'utilisateur

        Returns:
            dict: Informations de l'utilisateur (sans le mot de passe!)
        """
        if username not in self.users:
            return None

        user_data = self.users[username].copy()
        # Ne jamais exposer le hash complet en production!
        # Ici c'est pour l'éducation
        return {
            'username': username,
            'method': user_data['method'],
            'hash_preview': user_data['hash'][:20] + '...' if user_data['hash'] else None,
            'has_salt': user_data['salt'] is not None,
            'created_at': user_data['created_at']
        }

    def list_users(self) -> List[str]:
        """
        Liste tous les utilisateurs.

        Returns:
            list: Liste des noms d'utilisateurs
        """
        return list(self.users.keys())

    def export_for_john(self, filename: str, format: str = 'raw-md5') -> None:
        """
        Exporte les hashes dans un format compatible avec John the Ripper.

        Args:
            filename (str): Nom du fichier de sortie
            format (str): Format de sortie ('raw-md5', 'raw-sha256', etc.)
        """
        with open(filename, 'w') as f:
            for username, data in self.users.items():
                if format == 'raw-md5' and data['method'] == 'insecure_md5':
                    f.write(f"{username}:{data['hash']}\n")

                elif format == 'bcrypt' and data['method'] == 'bcrypt':
                    f.write(f"{username}:{data['hash']}\n")

                elif format == 'pbkdf2' and data['method'] == 'pbkdf2':
                    # Format John: username:$pbkdf2-sha256$iterations$salt$hash
                    f.write(f"{username}:$pbkdf2-sha256$100000${data['salt']}${data['hash']}\n")

    def demonstrate_database_breach(self) -> str:
        """
        Simule une violation de base de données et montre les différences
        entre les méthodes de hachage.

        Returns:
            str: Rapport de la violation simulée
        """
        output = []
        output.append("=" * 80)
        output.append("SIMULATION: VIOLATION DE BASE DE DONNÉES")
        output.append("=" * 80)
        output.append("Scénario: Un attaquant a volé la base de données...")
        output.append("")

        for username, data in self.users.items():
            output.append(f"Utilisateur: {username}")
            output.append(f"  Méthode: {data['method']}")
            output.append(f"  Hash: {data['hash'][:50]}...")

            if data['method'] == 'insecure_md5':
                output.append("  → VULNÉRABLE! MD5 sans salt")
                output.append("     Peut être cassé avec rainbow tables en secondes")

            elif data['method'] == 'sha256_salt':
                output.append(f"  Salt: {data['salt'][:32]}...")
                output.append("  → MIEUX: Salt unique, mais SHA-256 trop rapide")
                output.append("     Force brute possible avec GPU")

            elif data['method'] == 'pbkdf2':
                output.append(f"  Salt: {data['salt'][:32]}...")
                output.append("  → BON: PBKDF2 avec 100,000 itérations")
                output.append("     Ralentit les attaques significativement")

            elif data['method'] == 'bcrypt':
                output.append("  → EXCELLENT: bcrypt avec salt automatique")
                output.append("     Très résistant aux attaques par force brute")

            output.append("")

        output.append("=" * 80)
        output.append("LEÇONS:")
        output.append("  1. MD5/SHA-1 sans salt → Cassable en secondes")
        output.append("  2. SHA-256 avec salt → Mieux, mais GPU peut être rapide")
        output.append("  3. PBKDF2/bcrypt/scrypt → Conçus pour résister aux attaques")
        output.append("  4. Toujours utiliser un salt unique par utilisateur")
        output.append("  5. En production: bcrypt (rounds=12+) ou Argon2")
        output.append("=" * 80)

        return '\n'.join(output)

    def analyze_security(self) -> str:
        """
        Analyse la sécurité de la base de données.

        Returns:
            str: Rapport d'analyse de sécurité
        """
        total = len(self.users)
        if total == 0:
            return "Aucun utilisateur dans la base de données."

        # Compter par méthode
        methods = {}
        for data in self.users.values():
            method = data['method']
            methods[method] = methods.get(method, 0) + 1

        output = []
        output.append("=" * 80)
        output.append("ANALYSE DE SÉCURITÉ DE LA BASE DE DONNÉES")
        output.append("=" * 80)
        output.append(f"Nombre total d'utilisateurs: {total}")
        output.append("")
        output.append("Distribution par méthode:")

        security_scores = {
            'insecure_md5': (0, '✗ DANGEREUX'),
            'sha256_salt': (5, '△ MOYEN'),
            'pbkdf2': (8, '✓ BON'),
            'bcrypt': (10, '✓ EXCELLENT')
        }

        total_score = 0
        for method, count in methods.items():
            score, rating = security_scores.get(method, (0, '?'))
            percentage = (count / total) * 100
            output.append(f"  {method:15} : {count:3} ({percentage:5.1f}%) - {rating}")
            total_score += score * count

        avg_score = total_score / total if total > 0 else 0
        output.append("")
        output.append(f"Score de sécurité global: {avg_score:.1f}/10")

        if avg_score < 3:
            output.append("  État: ✗ CRITIQUE - Migration urgente nécessaire!")
        elif avg_score < 6:
            output.append("  État: △ FAIBLE - Amélioration recommandée")
        elif avg_score < 9:
            output.append("  État: ✓ BON - Sécurité acceptable")
        else:
            output.append("  État: ✓ EXCELLENT - Bonnes pratiques respectées")

        output.append("=" * 80)

        return '\n'.join(output)

    def migrate_to_bcrypt(self) -> str:
        """
        Simule la migration des mots de passe vers bcrypt.

        Note: En production, cela nécessiterait les mots de passe en clair
        (donc se fait lors de la prochaine connexion de chaque utilisateur).

        Returns:
            str: Rapport de migration
        """
        output = []
        output.append("=" * 80)
        output.append("SIMULATION: MIGRATION VERS BCRYPT")
        output.append("=" * 80)
        output.append("")
        output.append("En production, la migration se ferait ainsi:")
        output.append("  1. L'utilisateur se connecte avec son mot de passe")
        output.append("  2. Vérifier avec l'ancien hash")
        output.append("  3. Si correct: re-hacher avec bcrypt")
        output.append("  4. Remplacer l'ancien hash")
        output.append("")
        output.append("Avantages:")
        output.append("  ✓ Migration transparente pour l'utilisateur")
        output.append("  ✓ Pas besoin de réinitialiser les mots de passe")
        output.append("  ✓ Migration progressive (à chaque connexion)")
        output.append("")
        output.append("=" * 80)

        return '\n'.join(output)
