"""
Générateur de fichiers de hashes compatibles avec John the Ripper.

Crée des fichiers de hashes dans différents formats reconnus par JtR.
"""

import os
from typing import List, Dict, Optional
from pathlib import Path


class HashFileGenerator:
    """
    Génère des fichiers de hashes dans des formats compatibles John the Ripper.

    Supporte plusieurs formats de hash: MD5, SHA-256, SHA-512, bcrypt, etc.
    """

    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialise le générateur.

        Args:
            output_dir (str, optional): Répertoire de sortie pour les fichiers
        """
        self.output_dir = output_dir or os.getcwd()
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def generate_raw_md5(
        self,
        hashes: Dict[str, str],
        filename: str = 'hashes_md5.txt'
    ) -> str:
        """
        Génère un fichier de hashes MD5 au format John.

        Format: username:hash

        Args:
            hashes (dict): Dictionnaire {username: md5_hash}
            filename (str): Nom du fichier de sortie

        Returns:
            str: Chemin vers le fichier créé
        """
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w') as f:
            for username, hash_value in hashes.items():
                f.write(f"{username}:{hash_value}\n")

        return filepath

    def generate_raw_sha256(
        self,
        hashes: Dict[str, str],
        filename: str = 'hashes_sha256.txt'
    ) -> str:
        """
        Génère un fichier de hashes SHA-256 au format John.

        Format: username:hash

        Args:
            hashes (dict): Dictionnaire {username: sha256_hash}
            filename (str): Nom du fichier de sortie

        Returns:
            str: Chemin vers le fichier créé
        """
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w') as f:
            for username, hash_value in hashes.items():
                f.write(f"{username}:{hash_value}\n")

        return filepath

    def generate_raw_sha512(
        self,
        hashes: Dict[str, str],
        filename: str = 'hashes_sha512.txt'
    ) -> str:
        """
        Génère un fichier de hashes SHA-512 au format John.

        Format: username:hash

        Args:
            hashes (dict): Dictionnaire {username: sha512_hash}
            filename (str): Nom du fichier de sortie

        Returns:
            str: Chemin vers le fichier créé
        """
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w') as f:
            for username, hash_value in hashes.items():
                f.write(f"{username}:{hash_value}\n")

        return filepath

    def generate_bcrypt(
        self,
        hashes: Dict[str, str],
        filename: str = 'hashes_bcrypt.txt'
    ) -> str:
        """
        Génère un fichier de hashes bcrypt au format John.

        Format: username:$2a$rounds$salt_and_hash

        Args:
            hashes (dict): Dictionnaire {username: bcrypt_hash_complet}
            filename (str): Nom du fichier de sortie

        Returns:
            str: Chemin vers le fichier créé
        """
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w') as f:
            for username, hash_value in hashes.items():
                # bcrypt hash contient déjà le format complet $2a$...$...
                f.write(f"{username}:{hash_value}\n")

        return filepath

    def generate_salted_sha256(
        self,
        hashes: Dict[str, Dict[str, str]],
        filename: str = 'hashes_sha256_salted.txt'
    ) -> str:
        """
        Génère un fichier de hashes SHA-256 avec salt au format John.

        Format: username:$dynamic_4$hash$HEX$salt

        Args:
            hashes (dict): Dictionnaire {username: {'hash': ..., 'salt': ...}}
            filename (str): Nom du fichier de sortie

        Returns:
            str: Chemin vers le fichier créé
        """
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w') as f:
            for username, data in hashes.items():
                hash_value = data['hash']
                salt = data['salt']

                # Format dynamic pour SHA256(salt.password)
                # Note: Le format exact dépend de comment le hash a été créé
                f.write(f"{username}:$dynamic_4${hash_value}$HEX${salt}\n")

        return filepath

    def generate_pbkdf2_sha256(
        self,
        hashes: Dict[str, Dict[str, any]],
        filename: str = 'hashes_pbkdf2.txt'
    ) -> str:
        """
        Génère un fichier de hashes PBKDF2-SHA256 au format John.

        Format: username:$pbkdf2-sha256$iterations$salt$hash

        Args:
            hashes (dict): Dictionnaire {username: {'hash': ..., 'salt': ..., 'iterations': ...}}
            filename (str): Nom du fichier de sortie

        Returns:
            str: Chemin vers le fichier créé
        """
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w') as f:
            for username, data in hashes.items():
                hash_value = data['hash']
                salt = data['salt']
                iterations = data.get('iterations', 100000)

                f.write(f"{username}:$pbkdf2-sha256${iterations}${salt}${hash_value}\n")

        return filepath

    def generate_from_password_database(
        self,
        password_db,
        filename: str = 'hashes_from_db.txt'
    ) -> Dict[str, str]:
        """
        Génère des fichiers de hashes depuis une PasswordDatabase.

        Crée un fichier séparé pour chaque méthode de hachage.

        Args:
            password_db: Instance de PasswordDatabase
            filename: Préfixe pour les noms de fichiers

        Returns:
            dict: Dictionnaire {method: filepath}
        """
        files_created = {}

        # Grouper les utilisateurs par méthode
        users_by_method = {}
        for username, user_data in password_db.users.items():
            method = user_data['method']
            if method not in users_by_method:
                users_by_method[method] = {}

            users_by_method[method][username] = user_data

        # Créer un fichier pour chaque méthode
        for method, users in users_by_method.items():
            if method == 'insecure_md5':
                hashes = {u: d['hash'] for u, d in users.items()}
                filepath = self.generate_raw_md5(hashes, f"{filename}_md5.txt")
                files_created['md5'] = filepath

            elif method == 'sha256_salt':
                hashes = {
                    u: {'hash': d['hash'], 'salt': d['salt']}
                    for u, d in users.items()
                }
                filepath = self.generate_salted_sha256(hashes, f"{filename}_sha256.txt")
                files_created['sha256'] = filepath

            elif method == 'bcrypt':
                hashes = {u: d['hash'] for u, d in users.items()}
                filepath = self.generate_bcrypt(hashes, f"{filename}_bcrypt.txt")
                files_created['bcrypt'] = filepath

            elif method == 'pbkdf2':
                hashes = {
                    u: {
                        'hash': d['hash'],
                        'salt': d['salt'],
                        'iterations': 100000
                    }
                    for u, d in users.items()
                }
                filepath = self.generate_pbkdf2_sha256(hashes, f"{filename}_pbkdf2.txt")
                files_created['pbkdf2'] = filepath

        return files_created

    def create_test_hashes(self, passwords: List[str], method: str = 'md5') -> str:
        """
        Crée un fichier de test avec des hashes de mots de passe connus.

        Utile pour démonstration et tests.

        Args:
            passwords (list): Liste de mots de passe
            method (str): Méthode de hachage ('md5', 'sha256', 'sha512')

        Returns:
            str: Chemin vers le fichier créé
        """
        import hashlib

        hashes = {}

        for i, password in enumerate(passwords):
            username = f"user{i+1}"

            if method == 'md5':
                hash_obj = hashlib.md5(password.encode())
            elif method == 'sha256':
                hash_obj = hashlib.sha256(password.encode())
            elif method == 'sha512':
                hash_obj = hashlib.sha512(password.encode())
            else:
                raise ValueError(f"Méthode non supportée: {method}")

            hashes[username] = hash_obj.hexdigest()

        # Générer le fichier approprié
        if method == 'md5':
            return self.generate_raw_md5(hashes, 'test_hashes_md5.txt')
        elif method == 'sha256':
            return self.generate_raw_sha256(hashes, 'test_hashes_sha256.txt')
        elif method == 'sha512':
            return self.generate_raw_sha512(hashes, 'test_hashes_sha512.txt')

    def get_format_hint(self, method: str) -> Optional[str]:
        """
        Retourne le format John the Ripper pour une méthode donnée.

        Args:
            method (str): Méthode de hachage

        Returns:
            str: Format JtR (ex: 'raw-md5', 'bcrypt')
        """
        format_map = {
            'insecure_md5': 'raw-md5',
            'md5': 'raw-md5',
            'sha256': 'raw-sha256',
            'sha256_salt': 'dynamic',
            'sha512': 'raw-sha512',
            'bcrypt': 'bcrypt',
            'pbkdf2': 'pbkdf2-hmac-sha256'
        }

        return format_map.get(method)

    def display_file_info(self, filepath: str) -> str:
        """
        Affiche des informations sur un fichier de hashes.

        Args:
            filepath (str): Chemin vers le fichier

        Returns:
            str: Informations formatées
        """
        if not os.path.exists(filepath):
            return f"Fichier non trouvé: {filepath}"

        with open(filepath, 'r') as f:
            lines = f.readlines()

        output = []
        output.append("="*60)
        output.append(f"FICHIER: {os.path.basename(filepath)}")
        output.append("="*60)
        output.append(f"Chemin complet: {filepath}")
        output.append(f"Nombre de hashes: {len(lines)}")
        output.append("")
        output.append("Aperçu (5 premières lignes):")
        output.append("-"*60)

        for i, line in enumerate(lines[:5]):
            output.append(f"  {i+1}. {line.strip()}")

        output.append("="*60)

        return '\n'.join(output)
