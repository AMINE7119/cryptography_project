"""
Wrapper Python pour John the Ripper.

Fournit une interface pour interagir avec l'outil de ligne de commande John the Ripper.
"""

import subprocess
import os
import shutil
from typing import Optional, List, Dict, Tuple
from pathlib import Path


class JohnTheRipperWrapper:
    """
    Wrapper pour interagir avec John the Ripper via subprocess.

    Permet de lancer des attaques, récupérer les résultats, et gérer les sessions.
    """

    def __init__(self, john_path: Optional[str] = None):
        """
        Initialise le wrapper JtR.

        Args:
            john_path (str, optional): Chemin vers l'exécutable john.
                                      Si None, cherche dans le PATH.
        """
        self.john_path = john_path or self._find_john()
        self.is_installed = self.check_installation()

    def _find_john(self) -> str:
        """
        Cherche l'exécutable john dans le PATH.

        Returns:
            str: Chemin vers john ou 'john' par défaut
        """
        # Essayer de trouver john dans le PATH
        john_exe = shutil.which('john')
        if john_exe:
            return john_exe

        # Chemins communs sur différents OS
        common_paths = [
            '/usr/bin/john',
            '/usr/local/bin/john',
            'C:\\john\\run\\john.exe',
            'john'  # Fallback
        ]

        for path in common_paths:
            if os.path.exists(path):
                return path

        return 'john'  # Assume it's in PATH

    def check_installation(self) -> bool:
        """
        Vérifie si John the Ripper est installé et accessible.

        Returns:
            bool: True si JtR est installé
        """
        try:
            result = subprocess.run(
                [self.john_path, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def get_version(self) -> Optional[str]:
        """
        Récupère la version de John the Ripper.

        Returns:
            str: Version de JtR ou None si non installé
        """
        if not self.is_installed:
            return None

        try:
            result = subprocess.run(
                [self.john_path, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Parse la première ligne
            return result.stdout.split('\n')[0]
        except subprocess.SubprocessError:
            return None

    def list_formats(self) -> List[str]:
        """
        Liste tous les formats de hash supportés par JtR.

        Returns:
            list: Liste des formats supportés
        """
        if not self.is_installed:
            return []

        try:
            result = subprocess.run(
                [self.john_path, '--list=formats'],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Parser la sortie
            formats = []
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and not line.startswith('User formats'):
                    formats.extend(line.split(','))

            return [f.strip() for f in formats if f.strip()]

        except subprocess.SubprocessError:
            return []

    def crack_hash_file(
        self,
        hash_file: str,
        wordlist: Optional[str] = None,
        format_type: Optional[str] = None,
        rules: Optional[str] = None,
        session_name: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> Tuple[bool, str]:
        """
        Lance John the Ripper sur un fichier de hashes.

        Args:
            hash_file (str): Chemin vers le fichier de hashes
            wordlist (str, optional): Chemin vers la wordlist
            format_type (str, optional): Format de hash (ex: 'raw-md5', 'bcrypt')
            rules (str, optional): Règles à appliquer (ex: 'best64')
            session_name (str, optional): Nom de la session
            timeout (int, optional): Timeout en secondes

        Returns:
            tuple: (succès, message/erreur)
        """
        if not self.is_installed:
            return False, "John the Ripper n'est pas installé"

        if not os.path.exists(hash_file):
            return False, f"Fichier de hash non trouvé: {hash_file}"

        # Construire la commande
        cmd = [self.john_path]

        if format_type:
            cmd.extend(['--format=' + format_type])

        if wordlist:
            if not os.path.exists(wordlist):
                return False, f"Wordlist non trouvée: {wordlist}"
            cmd.extend(['--wordlist=' + wordlist])

        if rules:
            cmd.extend(['--rules=' + rules])

        if session_name:
            cmd.extend(['--session=' + session_name])

        cmd.append(hash_file)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return True, result.stdout + result.stderr

        except subprocess.TimeoutExpired:
            return False, f"Timeout dépassé ({timeout}s)"

        except subprocess.SubprocessError as e:
            return False, f"Erreur lors de l'exécution: {e}"

    def show_cracked(self, hash_file: str, format_type: Optional[str] = None) -> Dict[str, str]:
        """
        Récupère les mots de passe cassés pour un fichier de hashes.

        Args:
            hash_file (str): Chemin vers le fichier de hashes
            format_type (str, optional): Format de hash

        Returns:
            dict: Dictionnaire {username: password}
        """
        if not self.is_installed:
            return {}

        if not os.path.exists(hash_file):
            return {}

        # Construire la commande
        cmd = [self.john_path, '--show']

        if format_type:
            cmd.extend(['--format=' + format_type])

        cmd.append(hash_file)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            # Parser la sortie: username:password
            cracked = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if ':' in line and not line.startswith('0 password'):
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        username, password = parts
                        cracked[username] = password

            return cracked

        except subprocess.SubprocessError:
            return {}

    def benchmark(self, format_type: Optional[str] = None) -> Dict[str, int]:
        """
        Lance un benchmark de John the Ripper.

        Args:
            format_type (str, optional): Format à benchmarker (None = tous)

        Returns:
            dict: Résultats du benchmark {format: hashes_per_sec}
        """
        if not self.is_installed:
            return {}

        cmd = [self.john_path, '--test']

        if format_type:
            cmd.append('--format=' + format_type)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            # Parser les résultats
            benchmarks = {}
            for line in result.stdout.split('\n'):
                # Format typique: "Raw-MD5 [MD5 128/128 AVX 4x3]    123456 c/s"
                if 'c/s' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        format_name = parts[0]
                        try:
                            # Extraire le nombre (peut être "123456" ou "123K")
                            speed_str = parts[-2]
                            if 'K' in speed_str:
                                speed = int(float(speed_str.replace('K', '')) * 1000)
                            elif 'M' in speed_str:
                                speed = int(float(speed_str.replace('M', '')) * 1000000)
                            else:
                                speed = int(speed_str)

                            benchmarks[format_name] = speed
                        except ValueError:
                            continue

            return benchmarks

        except subprocess.SubprocessError:
            return {}

    def incremental_mode(
        self,
        hash_file: str,
        format_type: Optional[str] = None,
        charset: str = 'ASCII',
        timeout: Optional[int] = None
    ) -> Tuple[bool, str]:
        """
        Lance une attaque en mode incrémental (brute force intelligent).

        Args:
            hash_file (str): Fichier de hashes
            format_type (str, optional): Format de hash
            charset (str): Charset à utiliser ('ASCII', 'Alpha', 'Digits', etc.)
            timeout (int, optional): Timeout en secondes

        Returns:
            tuple: (succès, message)
        """
        if not self.is_installed:
            return False, "John the Ripper n'est pas installé"

        cmd = [self.john_path, '--incremental=' + charset]

        if format_type:
            cmd.extend(['--format=' + format_type])

        cmd.append(hash_file)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return True, result.stdout + result.stderr

        except subprocess.TimeoutExpired:
            return False, f"Timeout dépassé ({timeout}s)"

        except subprocess.SubprocessError as e:
            return False, f"Erreur: {e}"

    def get_session_status(self, session_name: str) -> Optional[Dict]:
        """
        Récupère le statut d'une session JtR.

        Args:
            session_name (str): Nom de la session

        Returns:
            dict: Informations sur la session ou None
        """
        if not self.is_installed:
            return None

        cmd = [self.john_path, '--status=' + session_name]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )

            # Parser basique du statut
            info = {
                'session': session_name,
                'output': result.stdout
            }

            return info

        except subprocess.SubprocessError:
            return None
