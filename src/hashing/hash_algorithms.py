"""
Implémentation des algorithmes de hachage modernes.
"""

import hashlib
import bcrypt
from typing import Tuple, Dict
import time


class HashEngine:
    """Moteur de hachage implémentant plusieurs algorithmes modernes."""

    def __init__(self):
        """Initialise le moteur de hachage."""
        self.algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt']

    def hash_md5(self, data: str) -> str:
        """
        Génère un hash MD5 (OBSOLÈTE - à des fins éducatives uniquement).

        MD5 est cassé et ne doit PAS être utilisé pour la sécurité.
        Vulnérable aux collisions.

        Args:
            data (str): Données à hacher

        Returns:
            str: Hash MD5 en hexadécimal
        """
        return hashlib.md5(data.encode()).hexdigest()

    def hash_sha1(self, data: str) -> str:
        """
        Génère un hash SHA-1 (DÉPRÉCIÉ - à des fins éducatives uniquement).

        SHA-1 est cassé depuis 2017 (attaque de collision SHAttered).
        Ne doit pas être utilisé pour de nouvelles applications.

        Args:
            data (str): Données à hacher

        Returns:
            str: Hash SHA-1 en hexadécimal
        """
        return hashlib.sha1(data.encode()).hexdigest()

    def hash_sha256(self, data: str) -> str:
        """
        Génère un hash SHA-256 (MODERNE - sécurisé).

        SHA-256 fait partie de la famille SHA-2, considéré sûr.
        Utilisé dans Bitcoin, SSL/TLS, etc.

        Args:
            data (str): Données à hacher

        Returns:
            str: Hash SHA-256 en hexadécimal
        """
        return hashlib.sha256(data.encode()).hexdigest()

    def hash_sha512(self, data: str) -> str:
        """
        Génère un hash SHA-512 (MODERNE - très sécurisé).

        Version plus forte de SHA-2 avec sortie de 512 bits.
        Plus lent que SHA-256 mais plus sûr.

        Args:
            data (str): Données à hacher

        Returns:
            str: Hash SHA-512 en hexadécimal
        """
        return hashlib.sha512(data.encode()).hexdigest()

    def hash_bcrypt(self, password: str, rounds: int = 12) -> str:
        """
        Génère un hash bcrypt (RECOMMANDÉ pour mots de passe).

        Bcrypt inclut automatiquement:
        - Un salt aléatoire
        - Un coût adaptatif (ralentissement intentionnel)
        - Protection contre les attaques par force brute

        Args:
            password (str): Mot de passe à hacher
            rounds (int): Nombre de rounds (4-31, défaut=12)
                         Chaque incrément double le temps de calcul

        Returns:
            str: Hash bcrypt complet (inclut salt et rounds)
        """
        # Générer un salt avec le nombre de rounds spécifié
        salt = bcrypt.gensalt(rounds=rounds)
        # Hacher le mot de passe
        hashed = bcrypt.hashpw(password.encode(), salt)
        return hashed.decode()

    def verify_bcrypt(self, password: str, hashed: str) -> bool:
        """
        Vérifie un mot de passe contre un hash bcrypt.

        Args:
            password (str): Mot de passe à vérifier
            hashed (str): Hash bcrypt stocké

        Returns:
            bool: True si le mot de passe correspond
        """
        try:
            return bcrypt.checkpw(password.encode(), hashed.encode())
        except Exception:
            return False

    def hash_all(self, data: str) -> Dict[str, str]:
        """
        Génère tous les hashes pour une comparaison.

        Args:
            data (str): Données à hacher

        Returns:
            dict: Dictionnaire {algorithme: hash}
        """
        return {
            'MD5': self.hash_md5(data),
            'SHA-1': self.hash_sha1(data),
            'SHA-256': self.hash_sha256(data),
            'SHA-512': self.hash_sha512(data),
            'bcrypt': self.hash_bcrypt(data)
        }

    def compare_hashes(self, data: str) -> str:
        """
        Compare tous les algorithmes de hachage de manière visuelle.

        Args:
            data (str): Données à hacher

        Returns:
            str: Tableau de comparaison formaté
        """
        hashes = self.hash_all(data)

        output = []
        output.append("=" * 80)
        output.append("COMPARAISON DES ALGORITHMES DE HACHAGE")
        output.append("=" * 80)
        output.append(f"Données d'entrée: {data}")
        output.append("=" * 80)
        output.append("")
        output.append(f"{'Algorithme':<12} | {'Longueur':<10} | {'Hash'}")
        output.append("-" * 80)

        for algo, hash_value in hashes.items():
            length = len(hash_value)
            # Tronquer pour l'affichage
            display_hash = hash_value if len(hash_value) <= 50 else hash_value[:47] + "..."
            output.append(f"{algo:<12} | {length:<10} | {display_hash}")

        output.append("=" * 80)
        output.append("")
        output.append("NOTES DE SÉCURITÉ:")
        output.append("  ✗ MD5     : CASSÉ - Ne pas utiliser (collisions trouvées)")
        output.append("  ✗ SHA-1   : DÉPRÉCIÉ - Cassé en 2017 (SHAttered attack)")
        output.append("  ✓ SHA-256 : SÛR - Standard moderne (Bitcoin, SSL/TLS)")
        output.append("  ✓ SHA-512 : TRÈS SÛR - Version renforcée de SHA-2")
        output.append("  ✓ bcrypt  : RECOMMANDÉ - Spécialement conçu pour mots de passe")
        output.append("")
        output.append("Pour mots de passe: Utilisez TOUJOURS bcrypt, scrypt ou Argon2")
        output.append("=" * 80)

        return '\n'.join(output)

    def benchmark_algorithms(self, data: str = "password123", iterations: int = 1000) -> Dict[str, float]:
        """
        Compare les performances des algorithmes de hachage.

        Args:
            data (str): Données à hacher
            iterations (int): Nombre d'itérations pour le benchmark

        Returns:
            dict: Temps d'exécution en secondes pour chaque algorithme
        """
        results = {}

        # MD5
        start = time.time()
        for _ in range(iterations):
            self.hash_md5(data)
        results['MD5'] = time.time() - start

        # SHA-1
        start = time.time()
        for _ in range(iterations):
            self.hash_sha1(data)
        results['SHA-1'] = time.time() - start

        # SHA-256
        start = time.time()
        for _ in range(iterations):
            self.hash_sha256(data)
        results['SHA-256'] = time.time() - start

        # SHA-512
        start = time.time()
        for _ in range(iterations):
            self.hash_sha512(data)
        results['SHA-512'] = time.time() - start

        # bcrypt (moins d'itérations car plus lent)
        bcrypt_iterations = min(10, iterations // 100)
        start = time.time()
        for _ in range(bcrypt_iterations):
            self.hash_bcrypt(data, rounds=10)
        # Normaliser au nombre d'itérations standard
        results['bcrypt'] = (time.time() - start) * (iterations / bcrypt_iterations)

        return results

    def demonstrate_collision_resistance(self, data1: str, data2: str) -> str:
        """
        Démontre la résistance aux collisions des algorithmes.

        Montre que même un changement minime produit un hash complètement différent.

        Args:
            data1 (str): Première donnée
            data2 (str): Deuxième donnée (légèrement différente)

        Returns:
            str: Démonstration formatée
        """
        output = []
        output.append("=" * 80)
        output.append("DÉMONSTRATION: RÉSISTANCE AUX COLLISIONS")
        output.append("=" * 80)
        output.append(f"Données 1: {data1}")
        output.append(f"Données 2: {data2}")
        output.append("")
        output.append("Même un changement d'un seul caractère produit un hash totalement différent!")
        output.append("=" * 80)
        output.append("")

        # SHA-256 comparison
        hash1 = self.hash_sha256(data1)
        hash2 = self.hash_sha256(data2)

        output.append("SHA-256:")
        output.append(f"  Hash 1: {hash1}")
        output.append(f"  Hash 2: {hash2}")

        # Calculer le pourcentage de différence
        diff_count = sum(c1 != c2 for c1, c2 in zip(hash1, hash2))
        diff_percent = (diff_count / len(hash1)) * 100

        output.append(f"  Différence: {diff_count}/{len(hash1)} caractères ({diff_percent:.1f}%)")
        output.append("")
        output.append("Ceci est appelé 'l'effet avalanche' - crucial pour la sécurité!")
        output.append("=" * 80)

        return '\n'.join(output)

    def get_algorithm_info(self, algorithm: str) -> Dict[str, str]:
        """
        Retourne les informations sur un algorithme de hachage.

        Args:
            algorithm (str): Nom de l'algorithme

        Returns:
            dict: Informations détaillées
        """
        info = {
            'md5': {
                'name': 'MD5',
                'output_size': '128 bits (32 caractères hex)',
                'security': 'CASSÉ - NE PAS UTILISER',
                'speed': 'Très rapide',
                'use_case': 'Checksums non-cryptographiques uniquement',
                'year': '1991',
                'broken': '2004 (collisions trouvées)'
            },
            'sha1': {
                'name': 'SHA-1',
                'output_size': '160 bits (40 caractères hex)',
                'security': 'DÉPRÉCIÉ - Cassé',
                'speed': 'Rapide',
                'use_case': 'Git (legacy), checksums',
                'year': '1995',
                'broken': '2017 (SHAttered attack)'
            },
            'sha256': {
                'name': 'SHA-256',
                'output_size': '256 bits (64 caractères hex)',
                'security': 'SÛR - Standard actuel',
                'speed': 'Moyen',
                'use_case': 'Bitcoin, SSL/TLS, signatures',
                'year': '2001',
                'broken': 'Non cassé'
            },
            'sha512': {
                'name': 'SHA-512',
                'output_size': '512 bits (128 caractères hex)',
                'security': 'TRÈS SÛR',
                'speed': 'Moyen-Lent',
                'use_case': 'Haute sécurité, intégrité',
                'year': '2001',
                'broken': 'Non cassé'
            },
            'bcrypt': {
                'name': 'bcrypt',
                'output_size': '184 bits + salt + rounds',
                'security': 'EXCELLENT - Recommandé pour mots de passe',
                'speed': 'Intentionnellement lent',
                'use_case': 'Stockage de mots de passe',
                'year': '1999',
                'broken': 'Non cassé'
            }
        }

        return info.get(algorithm.lower(), {})
