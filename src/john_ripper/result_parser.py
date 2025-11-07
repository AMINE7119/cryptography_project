"""
Parser de résultats pour John the Ripper.

Analyse et formate les sorties de John the Ripper.
"""

from typing import Dict, List, Tuple, Optional
import re
from datetime import datetime


class JTRResultParser:
    """
    Parse et analyse les résultats de John the Ripper.

    Extrait les informations utiles des sorties de JtR.
    """

    @staticmethod
    def parse_show_output(output: str) -> Dict[str, str]:
        """
        Parse la sortie de 'john --show'.

        Args:
            output (str): Sortie de la commande --show

        Returns:
            dict: Dictionnaire {username: password}
        """
        cracked = {}

        for line in output.split('\n'):
            line = line.strip()

            # Ignorer les lignes de statistiques
            if not line or 'password hash' in line.lower():
                continue

            # Format: username:password ou username:password:autres_champs
            if ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    username = parts[0]
                    password = parts[1]

                    # Vérifier que ce n'est pas une ligne de hash
                    if not password.startswith('$'):
                        cracked[username] = password

        return cracked

    @staticmethod
    def parse_crack_output(output: str) -> Dict[str, any]:
        """
        Parse la sortie principale de John lors du cassage.

        Extrait les mots de passe trouvés et les statistiques.

        Args:
            output (str): Sortie de john

        Returns:
            dict: Informations extraites
        """
        result = {
            'cracked_passwords': {},
            'session_info': {},
            'warnings': [],
            'progress': {}
        }

        # Pattern pour les mots de passe cassés
        # Format typique: "password         (username)"
        password_pattern = r'([^\s]+)\s+\(([^)]+)\)'

        for line in output.split('\n'):
            line = line.strip()

            # Mots de passe cassés
            match = re.search(password_pattern, line)
            if match:
                password, username = match.groups()
                result['cracked_passwords'][username] = password

            # Warnings et messages importants
            if 'Warning' in line or 'warning' in line:
                result['warnings'].append(line)

            # Informations de session
            if 'Session completed' in line or 'Session aborted' in line:
                result['session_info']['status'] = line

        return result

    @staticmethod
    def parse_status_output(output: str) -> Dict[str, any]:
        """
        Parse la sortie de 'john --status'.

        Args:
            output (str): Sortie de --status

        Returns:
            dict: Informations de statut
        """
        status = {
            'session_name': None,
            'time_running': None,
            'progress': None,
            'candidates_tested': None,
            'speed': None
        }

        for line in output.split('\n'):
            line = line.strip()

            if 'Session:' in line:
                status['session_name'] = line.split(':', 1)[1].strip()

            elif 'Time running:' in line or 'time:' in line.lower():
                # Extraire le temps
                match = re.search(r'(\d+:\d+:\d+)', line)
                if match:
                    status['time_running'] = match.group(1)

            elif 'Progress:' in line or 'progress:' in line.lower():
                # Extraire le pourcentage de progression
                match = re.search(r'(\d+(?:\.\d+)?)\s*%', line)
                if match:
                    status['progress'] = float(match.group(1))

            elif 'c/s' in line:
                # Extraire la vitesse (candidates per second)
                match = re.search(r'(\d+(?:\.\d+)?[KMG]?)\s*c/s', line)
                if match:
                    status['speed'] = match.group(1)

        return status

    @staticmethod
    def parse_format_list(output: str) -> List[str]:
        """
        Parse la sortie de 'john --list=formats'.

        Args:
            output (str): Sortie de --list=formats

        Returns:
            list: Liste des formats
        """
        formats = []

        for line in output.split('\n'):
            line = line.strip()

            # Ignorer les en-têtes
            if not line or 'User formats' in line or 'Dynamic' in line:
                continue

            # Les formats peuvent être séparés par des virgules
            if ',' in line:
                formats.extend([f.strip() for f in line.split(',')])
            else:
                formats.append(line)

        return [f for f in formats if f]

    @staticmethod
    def calculate_crack_rate(cracked: int, total: int) -> float:
        """
        Calcule le taux de cassage.

        Args:
            cracked (int): Nombre de hashes cassés
            total (int): Nombre total de hashes

        Returns:
            float: Taux de cassage en pourcentage
        """
        if total == 0:
            return 0.0

        return (cracked / total) * 100

    @staticmethod
    def format_crack_results(
        cracked: Dict[str, str],
        total_hashes: int,
        time_taken: Optional[float] = None
    ) -> str:
        """
        Formate les résultats de cassage pour affichage.

        Args:
            cracked (dict): Mots de passe cassés {username: password}
            total_hashes (int): Nombre total de hashes
            time_taken (float, optional): Temps pris en secondes

        Returns:
            str: Résultats formatés
        """
        output = []
        output.append("="*80)
        output.append("RÉSULTATS DU CASSAGE JOHN THE RIPPER")
        output.append("="*80)

        crack_rate = JTRResultParser.calculate_crack_rate(len(cracked), total_hashes)

        output.append(f"Hashes cassés: {len(cracked)}/{total_hashes} ({crack_rate:.1f}%)")

        if time_taken:
            output.append(f"Temps écoulé: {time_taken:.2f} secondes")
            if len(cracked) > 0:
                rate = len(cracked) / time_taken
                output.append(f"Vitesse: {rate:.2f} hashes/seconde")

        output.append("")

        if cracked:
            output.append("MOTS DE PASSE TROUVÉS:")
            output.append("-"*80)

            # Trier par nom d'utilisateur
            for username in sorted(cracked.keys()):
                password = cracked[username]
                output.append(f"  {username:20} : {password}")

        else:
            output.append("Aucun mot de passe cassé.")

        output.append("="*80)

        return '\n'.join(output)

    @staticmethod
    def analyze_password_strength(passwords: List[str]) -> Dict[str, any]:
        """
        Analyse la force des mots de passe cassés.

        Args:
            passwords (list): Liste de mots de passe

        Returns:
            dict: Statistiques sur la force des mots de passe
        """
        stats = {
            'total': len(passwords),
            'by_length': {},
            'weak': 0,      # < 8 caractères
            'medium': 0,    # 8-11 caractères
            'strong': 0,    # 12+ caractères
            'numeric_only': 0,
            'alpha_only': 0,
            'alphanumeric': 0,
            'with_symbols': 0,
            'common_patterns': []
        }

        # Patterns communs
        common = ['123', 'password', 'admin', 'qwerty', 'azerty', '000', '111']

        for password in passwords:
            length = len(password)

            # Par longueur
            stats['by_length'][length] = stats['by_length'].get(length, 0) + 1

            # Force
            if length < 8:
                stats['weak'] += 1
            elif length < 12:
                stats['medium'] += 1
            else:
                stats['strong'] += 1

            # Type
            if password.isdigit():
                stats['numeric_only'] += 1
            elif password.isalpha():
                stats['alpha_only'] += 1
            elif password.isalnum():
                stats['alphanumeric'] += 1
            else:
                stats['with_symbols'] += 1

            # Patterns communs
            for pattern in common:
                if pattern.lower() in password.lower():
                    stats['common_patterns'].append(password)
                    break

        return stats

    @staticmethod
    def display_password_analysis(passwords: List[str]) -> str:
        """
        Affiche une analyse des mots de passe cassés.

        Args:
            passwords (list): Liste de mots de passe

        Returns:
            str: Analyse formatée
        """
        stats = JTRResultParser.analyze_password_strength(passwords)

        output = []
        output.append("="*80)
        output.append("ANALYSE DES MOTS DE PASSE CASSÉS")
        output.append("="*80)
        output.append(f"Nombre total: {stats['total']}")
        output.append("")

        output.append("FORCE DES MOTS DE PASSE:")
        output.append(f"  Faibles (< 8 car.)  : {stats['weak']:3} ({stats['weak']/stats['total']*100:5.1f}%)")
        output.append(f"  Moyens (8-11 car.)  : {stats['medium']:3} ({stats['medium']/stats['total']*100:5.1f}%)")
        output.append(f"  Forts (12+ car.)    : {stats['strong']:3} ({stats['strong']/stats['total']*100:5.1f}%)")
        output.append("")

        output.append("COMPOSITION:")
        output.append(f"  Numérique seulement : {stats['numeric_only']:3}")
        output.append(f"  Alphabétique seul.  : {stats['alpha_only']:3}")
        output.append(f"  Alphanumérique      : {stats['alphanumeric']:3}")
        output.append(f"  Avec symboles       : {stats['with_symbols']:3}")
        output.append("")

        if stats['common_patterns']:
            output.append(f"PATTERNS COMMUNS DÉTECTÉS: {len(stats['common_patterns'])}")
            for pwd in stats['common_patterns'][:10]:
                output.append(f"  - {pwd}")

        output.append("="*80)

        return '\n'.join(output)

    @staticmethod
    def compare_methods(results: Dict[str, Dict[str, str]]) -> str:
        """
        Compare les résultats de différentes méthodes de cassage.

        Args:
            results (dict): {method_name: {username: password}}

        Returns:
            str: Comparaison formatée
        """
        output = []
        output.append("="*80)
        output.append("COMPARAISON DES MÉTHODES DE CASSAGE")
        output.append("="*80)

        for method, cracked in results.items():
            output.append(f"\n{method}:")
            output.append(f"  Mots de passe cassés: {len(cracked)}")

            if cracked:
                passwords = list(cracked.values())
                stats = JTRResultParser.analyze_password_strength(passwords)

                output.append(f"  Faibles: {stats['weak']}, Moyens: {stats['medium']}, Forts: {stats['strong']}")

        output.append("="*80)

        return '\n'.join(output)
