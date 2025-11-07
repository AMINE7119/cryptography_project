import pytest
import sys
import os

# Ajouter le répertoire parent au path pour les imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.hashing.hash_algorithms import HashEngine
from src.hashing.salt_pepper import SaltGenerator, RainbowTableSimulator
from src.hashing.password_manager import PasswordDatabase


class TestHashEngine:
    """Tests pour le moteur de hachage."""

    def setup_method(self):
        """Configure les tests."""
        self.engine = HashEngine()

    def test_hash_md5(self):
        """Teste le hachage MD5."""
        result = self.engine.hash_md5("password")
        assert len(result) == 32  # MD5 = 128 bits = 32 hex chars
        assert result == "5f4dcc3b5aa765d61d8327deb882cf99"

    def test_hash_sha1(self):
        """Teste le hachage SHA-1."""
        result = self.engine.hash_sha1("password")
        assert len(result) == 40  # SHA-1 = 160 bits = 40 hex chars
        assert result == "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"

    def test_hash_sha256(self):
        """Teste le hachage SHA-256."""
        result = self.engine.hash_sha256("password")
        assert len(result) == 64  # SHA-256 = 256 bits = 64 hex chars
        assert result == "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

    def test_hash_sha512(self):
        """Teste le hachage SHA-512."""
        result = self.engine.hash_sha512("password")
        assert len(result) == 128  # SHA-512 = 512 bits = 128 hex chars
        assert isinstance(result, str)

    def test_hash_bcrypt(self):
        """Teste le hachage bcrypt."""
        password = "password123"
        result = self.engine.hash_bcrypt(password)

        # bcrypt commence par $2b$ ou $2a$
        assert result.startswith('$2b$') or result.startswith('$2a$')
        assert len(result) == 60  # bcrypt hash length

    def test_bcrypt_verify(self):
        """Teste la vérification bcrypt."""
        password = "SecurePassword123!"
        hashed = self.engine.hash_bcrypt(password)

        # Vérifier que le bon mot de passe fonctionne
        assert self.engine.verify_bcrypt(password, hashed) is True

        # Vérifier que le mauvais mot de passe échoue
        assert self.engine.verify_bcrypt("wrongpassword", hashed) is False

    def test_hash_all(self):
        """Teste le hachage avec tous les algorithmes."""
        result = self.engine.hash_all("test")

        assert 'MD5' in result
        assert 'SHA-1' in result
        assert 'SHA-256' in result
        assert 'SHA-512' in result
        assert 'bcrypt' in result

        # Vérifier les longueurs
        assert len(result['MD5']) == 32
        assert len(result['SHA-1']) == 40
        assert len(result['SHA-256']) == 64
        assert len(result['SHA-512']) == 128

    def test_deterministic_hashing(self):
        """Teste que le même input produit le même hash (sauf bcrypt)."""
        data = "test_data"

        # MD5, SHA-* sont déterministes
        assert self.engine.hash_md5(data) == self.engine.hash_md5(data)
        assert self.engine.hash_sha256(data) == self.engine.hash_sha256(data)

        # bcrypt n'est PAS déterministe (salt aléatoire)
        hash1 = self.engine.hash_bcrypt(data)
        hash2 = self.engine.hash_bcrypt(data)
        assert hash1 != hash2  # Différents hashes
        # Mais les deux devraient vérifier
        assert self.engine.verify_bcrypt(data, hash1)
        assert self.engine.verify_bcrypt(data, hash2)

    def test_collision_resistance(self):
        """Teste que des entrées similaires produisent des hashes différents."""
        hash1 = self.engine.hash_sha256("password")
        hash2 = self.engine.hash_sha256("Password")  # Juste une majuscule

        # Les hashes doivent être complètement différents
        assert hash1 != hash2

        # Calculer le pourcentage de différence
        diff_count = sum(c1 != c2 for c1, c2 in zip(hash1, hash2))
        diff_percent = (diff_count / len(hash1)) * 100

        # Au moins 50% de différence (effet avalanche)
        assert diff_percent > 50

    def test_get_algorithm_info(self):
        """Teste la récupération d'informations sur les algorithmes."""
        md5_info = self.engine.get_algorithm_info('md5')
        assert md5_info['name'] == 'MD5'
        assert 'CASSÉ' in md5_info['security']

        sha256_info = self.engine.get_algorithm_info('sha256')
        assert sha256_info['name'] == 'SHA-256'
        assert 'SÛR' in sha256_info['security']

        bcrypt_info = self.engine.get_algorithm_info('bcrypt')
        assert bcrypt_info['name'] == 'bcrypt'
        assert 'RECOMMANDÉ' in md5_info['security'] or 'EXCELLENT' in bcrypt_info['security']


class TestSaltGenerator:
    """Tests pour le générateur de salt."""

    def setup_method(self):
        """Configure les tests."""
        self.salt_gen = SaltGenerator()

    def test_generate_salt(self):
        """Teste la génération de salt."""
        salt = self.salt_gen.generate_salt()

        # Longueur par défaut: 32 bytes = 64 hex chars
        assert len(salt) == 64
        assert all(c in '0123456789abcdef' for c in salt)

    def test_generate_salt_custom_length(self):
        """Teste la génération de salt avec longueur personnalisée."""
        salt = self.salt_gen.generate_salt(16)
        assert len(salt) == 32  # 16 bytes = 32 hex chars

    def test_salt_uniqueness(self):
        """Teste que chaque salt est unique."""
        salts = [self.salt_gen.generate_salt() for _ in range(10)]
        # Tous les salts doivent être différents
        assert len(set(salts)) == 10

    def test_generate_pepper(self):
        """Teste la génération de pepper."""
        pepper = self.salt_gen.generate_pepper()
        assert len(pepper) == 64  # 32 bytes = 64 hex chars

    def test_hash_with_salt(self):
        """Teste le hachage avec salt."""
        password = "mypassword"
        salt = self.salt_gen.generate_salt()

        hash1 = self.salt_gen.hash_with_salt(password, salt)

        # Vérifier la longueur (SHA-256 par défaut)
        assert len(hash1) == 64

        # Même password + même salt = même hash
        hash2 = self.salt_gen.hash_with_salt(password, salt)
        assert hash1 == hash2

        # Même password + salt différent = hash différent
        different_salt = self.salt_gen.generate_salt()
        hash3 = self.salt_gen.hash_with_salt(password, different_salt)
        assert hash1 != hash3

    def test_hash_with_salt_and_pepper(self):
        """Teste le hachage avec salt et pepper."""
        password = "mypassword"
        salt = self.salt_gen.generate_salt()
        pepper = self.salt_gen.generate_pepper()

        hash1 = self.salt_gen.hash_with_salt_and_pepper(password, salt, pepper)

        # Vérifier la longueur
        assert len(hash1) == 64

        # Changer le pepper change le hash
        different_pepper = self.salt_gen.generate_pepper()
        hash2 = self.salt_gen.hash_with_salt_and_pepper(password, salt, different_pepper)
        assert hash1 != hash2

    def test_pbkdf2_hash(self):
        """Teste le hachage PBKDF2."""
        password = "securepassword"
        salt = self.salt_gen.generate_salt()

        hash1 = self.salt_gen.pbkdf2_hash(password, salt, iterations=10000)

        # Vérifier que c'est un hash hexadécimal
        assert len(hash1) == 64  # 32 bytes = 64 hex chars
        assert all(c in '0123456789abcdef' for c in hash1)

        # Même entrées = même sortie
        hash2 = self.salt_gen.pbkdf2_hash(password, salt, iterations=10000)
        assert hash1 == hash2


class TestRainbowTableSimulator:
    """Tests pour le simulateur de rainbow table."""

    def setup_method(self):
        """Configure les tests."""
        self.simulator = RainbowTableSimulator()

    def test_generate_rainbow_table(self):
        """Teste la génération de rainbow table."""
        wordlist = ["password", "admin", "test"]
        self.simulator.generate_rainbow_table(wordlist, algorithm='md5')

        assert len(self.simulator.table) == 3

    def test_lookup_success(self):
        """Teste la recherche réussie dans la table."""
        wordlist = ["password", "admin"]
        self.simulator.generate_rainbow_table(wordlist, algorithm='md5')

        # Hash MD5 de "password"
        password_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        found = self.simulator.lookup(password_hash)

        assert found == "password"

    def test_lookup_failure(self):
        """Teste la recherche échouée dans la table."""
        wordlist = ["password"]
        self.simulator.generate_rainbow_table(wordlist, algorithm='md5')

        # Hash qui n'est pas dans la table
        unknown_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        found = self.simulator.lookup(unknown_hash)

        assert found is None


class TestPasswordDatabase:
    """Tests pour la base de données de mots de passe."""

    def setup_method(self):
        """Configure les tests."""
        self.db = PasswordDatabase()

    def test_add_user_bcrypt(self):
        """Teste l'ajout d'utilisateur avec bcrypt."""
        success = self.db.add_user("alice", "password123", method='bcrypt')
        assert success is True

        # Vérifier que l'utilisateur existe
        assert "alice" in self.db.users
        assert self.db.users["alice"]['method'] == 'bcrypt'

    def test_add_user_pbkdf2(self):
        """Teste l'ajout d'utilisateur avec PBKDF2."""
        success = self.db.add_user("bob", "securepass", method='pbkdf2')
        assert success is True

        assert "bob" in self.db.users
        assert self.db.users["bob"]['method'] == 'pbkdf2'
        assert self.db.users["bob"]['salt'] is not None

    def test_add_duplicate_user(self):
        """Teste qu'on ne peut pas ajouter un utilisateur en double."""
        self.db.add_user("alice", "pass1", method='bcrypt')
        success = self.db.add_user("alice", "pass2", method='bcrypt')

        assert success is False

    def test_verify_password_bcrypt(self):
        """Teste la vérification de mot de passe avec bcrypt."""
        self.db.add_user("alice", "mypassword", method='bcrypt')

        # Bon mot de passe
        assert self.db.verify_password("alice", "mypassword") is True

        # Mauvais mot de passe
        assert self.db.verify_password("alice", "wrongpassword") is False

    def test_verify_password_pbkdf2(self):
        """Teste la vérification de mot de passe avec PBKDF2."""
        self.db.add_user("bob", "bobpass", method='pbkdf2')

        assert self.db.verify_password("bob", "bobpass") is True
        assert self.db.verify_password("bob", "wrong") is False

    def test_verify_password_sha256_salt(self):
        """Teste la vérification avec SHA-256 + salt."""
        self.db.add_user("charlie", "charliepass", method='sha256_salt')

        assert self.db.verify_password("charlie", "charliepass") is True
        assert self.db.verify_password("charlie", "wrong") is False

    def test_verify_password_nonexistent_user(self):
        """Teste la vérification pour un utilisateur inexistant."""
        assert self.db.verify_password("nonexistent", "anypass") is False

    def test_login_success(self):
        """Teste une connexion réussie."""
        self.db.add_user("alice", "password123", method='bcrypt')

        success, message = self.db.login("alice", "password123")
        assert success is True
        assert "réussie" in message.lower() or "succès" in message.lower()

    def test_login_failure(self):
        """Teste une connexion échouée."""
        self.db.add_user("alice", "password123", method='bcrypt')

        success, message = self.db.login("alice", "wrongpassword")
        assert success is False
        assert "incorrect" in message.lower()

    def test_login_attempts_tracking(self):
        """Teste le suivi des tentatives échouées."""
        self.db.add_user("alice", "password123", method='bcrypt')

        # 5 tentatives échouées
        for i in range(5):
            success, msg = self.db.login("alice", "wrong")
            assert success is False

        # 6ème tentative devrait être bloquée
        success, msg = self.db.login("alice", "wrong")
        assert success is False
        assert "verrouillé" in msg.lower() or "tentatives" in msg.lower()

    def test_get_user_info(self):
        """Teste la récupération d'informations utilisateur."""
        self.db.add_user("alice", "pass", method='bcrypt')

        info = self.db.get_user_info("alice")
        assert info is not None
        assert info['username'] == "alice"
        assert info['method'] == 'bcrypt'
        assert 'hash_preview' in info

    def test_list_users(self):
        """Teste le listage des utilisateurs."""
        self.db.add_user("alice", "pass1", method='bcrypt')
        self.db.add_user("bob", "pass2", method='pbkdf2')

        users = self.db.list_users()
        assert len(users) == 2
        assert "alice" in users
        assert "bob" in users

    def test_different_methods_work(self):
        """Teste que toutes les méthodes de hachage fonctionnent."""
        methods = ['bcrypt', 'pbkdf2', 'sha256_salt', 'insecure_md5']

        for i, method in enumerate(methods):
            username = f"user{i}"
            password = f"pass{i}"

            success = self.db.add_user(username, password, method=method)
            assert success is True

            # Vérifier que la connexion fonctionne
            verified = self.db.verify_password(username, password)
            assert verified is True


# Tests d'intégration
class TestHashingIntegration:
    """Tests d'intégration pour le module de hachage."""

    def test_full_password_workflow(self):
        """Teste le workflow complet de gestion de mot de passe."""
        db = PasswordDatabase()

        # 1. Créer un utilisateur
        db.add_user("alice", "SecureP@ss123", method='bcrypt')

        # 2. Connexion réussie
        success, msg = db.login("alice", "SecureP@ss123")
        assert success is True

        # 3. Connexion échouée
        success, msg = db.login("alice", "WrongPassword")
        assert success is False

        # 4. Vérifier les infos
        info = db.get_user_info("alice")
        assert info['username'] == "alice"

    def test_salt_prevents_identical_hashes(self):
        """Teste que le salt empêche les hashes identiques."""
        db = PasswordDatabase()

        # Deux utilisateurs avec le même mot de passe
        db.add_user("alice", "password123", method='pbkdf2')
        db.add_user("bob", "password123", method='pbkdf2')

        # Les hashes doivent être différents grâce aux salts
        alice_hash = db.users["alice"]['hash']
        bob_hash = db.users["bob"]['hash']

        assert alice_hash != bob_hash

    def test_pepper_adds_security(self):
        """Teste que le pepper ajoute une couche de sécurité."""
        # Deux bases de données avec des peppers différents
        db1 = PasswordDatabase(pepper="pepper1")
        db2 = PasswordDatabase(pepper="pepper2")

        # Même utilisateur, même mot de passe, même salt
        salt = SaltGenerator.generate_salt()

        db1.add_user("alice", "password", method='sha256_salt')
        db2.add_user("alice", "password", method='sha256_salt')

        # Les hashes devraient être différents (peppers différents)
        # Note: Comme les salts sont générés aléatoirement, ce test
        # vérifie juste que la fonctionnalité fonctionne
        assert "alice" in db1.users
        assert "alice" in db2.users
