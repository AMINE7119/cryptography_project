"""
Utilitaires pour les sels (salt) et poivres (pepper) cryptographiques.
"""

import secrets
import hashlib
from typing import Tuple


class SaltGenerator:
    """Génère et gère les sels cryptographiques."""

    @staticmethod
    def generate_salt(length: int = 32) -> str:
        """
        Génère un salt cryptographiquement sûr.

        Un salt est une valeur aléatoire ajoutée au mot de passe avant hachage.
        Il empêche les attaques par rainbow tables.

        Args:
            length (int): Longueur du salt en octets (défaut: 32)

        Returns:
            str: Salt en hexadécimal
        """
        return secrets.token_hex(length)

    @staticmethod
    def generate_pepper() -> str:
        """
        Génère un pepper cryptographiquement sûr.

        Un pepper est comme un salt, mais:
        - Stocké séparément (pas dans la base de données)
        - Partagé entre tous les utilisateurs
        - Ajoute une couche de sécurité supplémentaire

        Returns:
            str: Pepper en hexadécimal (64 caractères)
        """
        return secrets.token_hex(32)

    @staticmethod
    def hash_with_salt(password: str, salt: str, algorithm: str = 'sha256') -> str:
        """
        Hache un mot de passe avec un salt.

        Args:
            password (str): Mot de passe en clair
            salt (str): Salt à utiliser
            algorithm (str): Algorithme de hachage ('sha256' ou 'sha512')

        Returns:
            str: Hash du mot de passe salé
        """
        # Combiner le mot de passe et le salt
        salted = password + salt

        if algorithm == 'sha256':
            return hashlib.sha256(salted.encode()).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(salted.encode()).hexdigest()
        else:
            raise ValueError(f"Algorithme non supporté: {algorithm}")

    @staticmethod
    def hash_with_salt_and_pepper(password: str, salt: str, pepper: str,
                                   algorithm: str = 'sha256') -> str:
        """
        Hache un mot de passe avec salt et pepper.

        Le pepper ajoute une protection même si la base de données est compromise.

        Args:
            password (str): Mot de passe en clair
            salt (str): Salt unique par utilisateur
            pepper (str): Pepper partagé par l'application
            algorithm (str): Algorithme de hachage

        Returns:
            str: Hash du mot de passe salé et poivré
        """
        # Combiner: password + salt + pepper
        combined = password + salt + pepper

        if algorithm == 'sha256':
            return hashlib.sha256(combined.encode()).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(combined.encode()).hexdigest()
        else:
            raise ValueError(f"Algorithme non supporté: {algorithm}")

    @staticmethod
    def pbkdf2_hash(password: str, salt: str, iterations: int = 100000) -> str:
        """
        Utilise PBKDF2 pour dériver une clé depuis un mot de passe.

        PBKDF2 (Password-Based Key Derivation Function 2):
        - Applique le hachage de nombreuses fois (iterations)
        - Ralentit les attaques par force brute
        - Standard recommandé par NIST

        Args:
            password (str): Mot de passe en clair
            salt (str): Salt en hexadécimal
            iterations (int): Nombre d'itérations (100,000+ recommandé)

        Returns:
            str: Hash PBKDF2 en hexadécimal
        """
        # Convertir le salt hex en bytes
        salt_bytes = bytes.fromhex(salt)

        # Dériver la clé avec PBKDF2
        key = hashlib.pbkdf2_hmac(
            'sha256',  # Algorithme de hachage
            password.encode(),  # Mot de passe
            salt_bytes,  # Salt
            iterations  # Nombre d'itérations
        )

        return key.hex()

    @staticmethod
    def demonstrate_salt_importance() -> str:
        """
        Démontre pourquoi les salts sont cruciaux.

        Montre que le même mot de passe avec des salts différents
        produit des hashes complètement différents.

        Returns:
            str: Démonstration formatée
        """
        password = "password123"

        # Sans salt (MAUVAIS!)
        hash_no_salt = hashlib.sha256(password.encode()).hexdigest()

        # Avec différents salts
        salt1 = SaltGenerator.generate_salt(16)
        salt2 = SaltGenerator.generate_salt(16)

        hash_with_salt1 = SaltGenerator.hash_with_salt(password, salt1)
        hash_with_salt2 = SaltGenerator.hash_with_salt(password, salt2)

        output = []
        output.append("=" * 80)
        output.append("DÉMONSTRATION: IMPORTANCE DES SALTS")
        output.append("=" * 80)
        output.append(f"Mot de passe: {password}")
        output.append("")
        output.append("PROBLÈME - Sans salt (DANGEREUX!):")
        output.append(f"  Hash: {hash_no_salt}")
        output.append("  → Deux utilisateurs avec le même mot de passe auront le même hash")
        output.append("  → Vulnérable aux rainbow tables")
        output.append("")
        output.append("SOLUTION - Avec salts différents:")
        output.append(f"  Salt 1: {salt1}")
        output.append(f"  Hash 1: {hash_with_salt1}")
        output.append("")
        output.append(f"  Salt 2: {salt2}")
        output.append(f"  Hash 2: {hash_with_salt2}")
        output.append("")
        output.append("RÉSULTAT:")
        output.append("  ✓ Même mot de passe → Hashes différents grâce aux salts")
        output.append("  ✓ Rainbow tables inutilisables")
        output.append("  ✓ Impossible de détecter des mots de passe identiques")
        output.append("=" * 80)

        return '\n'.join(output)

    @staticmethod
    def compare_hashing_methods(password: str = "SecurePassword123!") -> str:
        """
        Compare différentes méthodes de hachage de mots de passe.

        Args:
            password (str): Mot de passe à utiliser pour la comparaison

        Returns:
            str: Comparaison formatée
        """
        import time

        salt = SaltGenerator.generate_salt()
        pepper = SaltGenerator.generate_pepper()

        output = []
        output.append("=" * 80)
        output.append("COMPARAISON DES MÉTHODES DE HACHAGE")
        output.append("=" * 80)
        output.append(f"Mot de passe: {password}")
        output.append("=" * 80)
        output.append("")

        # Méthode 1: Hash simple (MAUVAIS!)
        start = time.time()
        hash1 = hashlib.sha256(password.encode()).hexdigest()
        time1 = time.time() - start

        output.append("1. HASH SIMPLE (SHA-256) - ✗ DANGEREUX")
        output.append(f"   Hash: {hash1}")
        output.append(f"   Temps: {time1:.6f}s")
        output.append("   Problèmes:")
        output.append("   - Pas de salt → vulnérable aux rainbow tables")
        output.append("   - Trop rapide → force brute facile")
        output.append("")

        # Méthode 2: Hash avec salt
        start = time.time()
        hash2 = SaltGenerator.hash_with_salt(password, salt)
        time2 = time.time() - start

        output.append("2. HASH AVEC SALT (SHA-256) - △ MIEUX")
        output.append(f"   Salt: {salt[:32]}...")
        output.append(f"   Hash: {hash2}")
        output.append(f"   Temps: {time2:.6f}s")
        output.append("   Avantages:")
        output.append("   ✓ Salt unique → pas de rainbow tables")
        output.append("   Problèmes:")
        output.append("   - Toujours trop rapide")
        output.append("")

        # Méthode 3: PBKDF2
        start = time.time()
        hash3 = SaltGenerator.pbkdf2_hash(password, salt, iterations=100000)
        time3 = time.time() - start

        output.append("3. PBKDF2 (100,000 itérations) - ✓ BON")
        output.append(f"   Hash: {hash3}")
        output.append(f"   Temps: {time3:.6f}s")
        output.append("   Avantages:")
        output.append("   ✓ Salt unique")
        output.append("   ✓ Intentionnellement lent")
        output.append("   ✓ Standard NIST")
        output.append("")

        # Méthode 4: Avec pepper
        start = time.time()
        hash4 = SaltGenerator.hash_with_salt_and_pepper(password, salt, pepper)
        time4 = time.time() - start

        output.append("4. SALT + PEPPER - ✓ TRÈS BON")
        output.append(f"   Hash: {hash4}")
        output.append(f"   Temps: {time4:.6f}s")
        output.append("   Avantages:")
        output.append("   ✓ Salt unique par utilisateur")
        output.append("   ✓ Pepper secret de l'application")
        output.append("   ✓ Protection même si DB compromise")
        output.append("")

        output.append("=" * 80)
        output.append("RECOMMANDATION:")
        output.append("  Pour production → Utilisez bcrypt, scrypt ou Argon2")
        output.append("  Pour éducation → PBKDF2 avec salt + pepper")
        output.append("=" * 80)

        return '\n'.join(output)


class RainbowTableSimulator:
    """Simule des rainbow tables pour démonstration éducative."""

    def __init__(self):
        """Initialise le simulateur de rainbow tables."""
        self.table = {}

    def generate_rainbow_table(self, wordlist: list, algorithm: str = 'md5') -> None:
        """
        Génère une rainbow table depuis une liste de mots.

        AVERTISSEMENT: Ceci est pour démonstration éducative uniquement!
        Ne pas utiliser pour des activités malveillantes.

        Args:
            wordlist (list): Liste de mots de passe communs
            algorithm (str): Algorithme de hachage à utiliser
        """
        self.table = {}

        for word in wordlist:
            if algorithm == 'md5':
                hash_value = hashlib.md5(word.encode()).hexdigest()
            elif algorithm == 'sha1':
                hash_value = hashlib.sha1(word.encode()).hexdigest()
            elif algorithm == 'sha256':
                hash_value = hashlib.sha256(word.encode()).hexdigest()
            else:
                raise ValueError(f"Algorithme non supporté: {algorithm}")

            self.table[hash_value] = word

    def lookup(self, hash_value: str) -> str:
        """
        Recherche un hash dans la rainbow table.

        Args:
            hash_value (str): Hash à rechercher

        Returns:
            str: Mot de passe trouvé ou None
        """
        return self.table.get(hash_value, None)

    def demonstrate_rainbow_table_attack(self) -> str:
        """
        Démontre comment fonctionnent les rainbow tables.

        Returns:
            str: Démonstration formatée
        """
        # Mots de passe communs
        common_passwords = [
            "password", "123456", "password123", "admin",
            "letmein", "welcome", "monkey", "dragon",
            "master", "sunshine", "princess", "qwerty"
        ]

        # Générer la table
        self.generate_rainbow_table(common_passwords, 'md5')

        output = []
        output.append("=" * 80)
        output.append("DÉMONSTRATION: ATTAQUE PAR RAINBOW TABLE")
        output.append("=" * 80)
        output.append("")
        output.append("Étape 1: Générer la rainbow table (pré-calcul)")
        output.append(f"  Nombre de mots de passe: {len(common_passwords)}")
        output.append(f"  Taille de la table: {len(self.table)} hashes")
        output.append("")

        # Afficher quelques entrées
        output.append("Exemples de la table:")
        for i, (hash_val, password) in enumerate(list(self.table.items())[:5]):
            output.append(f"  {password:15} → {hash_val}")

        output.append("")
        output.append("Étape 2: Attaque sur des hashes sans salt")

        # Simuler des hashes capturés
        captured_hashes = {
            hashlib.md5("password".encode()).hexdigest(): "Utilisateur1",
            hashlib.md5("admin".encode()).hexdigest(): "Utilisateur2",
            hashlib.md5("ComplexP@ssw0rd!".encode()).hexdigest(): "Utilisateur3"
        }

        for hash_val, user in captured_hashes.items():
            found = self.lookup(hash_val)
            if found:
                output.append(f"  {user}: Hash cassé! Mot de passe = '{found}' ✗")
            else:
                output.append(f"  {user}: Pas dans la table ✓")

        output.append("")
        output.append("CONCLUSION:")
        output.append("  ✗ Sans salt → Rainbow tables efficaces")
        output.append("  ✓ Avec salt → Rainbow tables inutiles")
        output.append("     (il faudrait une table différente pour chaque salt)")
        output.append("=" * 80)

        return '\n'.join(output)
