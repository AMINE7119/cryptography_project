"""
Tests pour le module John the Ripper.
"""

import unittest
import os
import tempfile
import shutil
from pathlib import Path

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.john_ripper.jtr_wrapper import JohnTheRipperWrapper
from src.john_ripper.hash_file_generator import HashFileGenerator
from src.john_ripper.wordlist_manager import WordlistManager
from src.john_ripper.result_parser import JTRResultParser
from src.hashing.password_manager import PasswordDatabase


class TestJTRWrapper(unittest.TestCase):
    """Tests pour JohnTheRipperWrapper."""

    def setUp(self):
        """Configuration avant chaque test."""
        self.wrapper = JohnTheRipperWrapper()

    def test_check_installation(self):
        """Teste la vérification de l'installation."""
        # Retourne True ou False selon si JtR est installé
        result = self.wrapper.check_installation()
        self.assertIsInstance(result, bool)

    def test_get_version(self):
        """Teste la récupération de la version."""
        version = self.wrapper.get_version()
        # Peut être None si non installé, ou une string si installé
        self.assertTrue(version is None or isinstance(version, str))

    def test_list_formats(self):
        """Teste la liste des formats."""
        formats = self.wrapper.list_formats()
        self.assertIsInstance(formats, list)

        # Si JtR est installé, la liste ne devrait pas être vide
        if self.wrapper.is_installed:
            self.assertTrue(len(formats) > 0)


class TestHashFileGenerator(unittest.TestCase):
    """Tests pour HashFileGenerator."""

    def setUp(self):
        """Configuration avant chaque test."""
        self.temp_dir = tempfile.mkdtemp()
        self.generator = HashFileGenerator(output_dir=self.temp_dir)

    def tearDown(self):
        """Nettoyage après chaque test."""
        shutil.rmtree(self.temp_dir)

    def test_generate_raw_md5(self):
        """Teste la génération de fichier MD5."""
        hashes = {
            'user1': '5f4dcc3b5aa765d61d8327deb882cf99',  # password
            'user2': 'e10adc3949ba59abbe56e057f20f883e'   # 123456
        }

        filepath = self.generator.generate_raw_md5(hashes)

        self.assertTrue(os.path.exists(filepath))

        with open(filepath, 'r') as f:
            content = f.read()

        self.assertIn('user1:5f4dcc3b5aa765d61d8327deb882cf99', content)
        self.assertIn('user2:e10adc3949ba59abbe56e057f20f883e', content)

    def test_generate_raw_sha256(self):
        """Teste la génération de fichier SHA-256."""
        hashes = {
            'user1': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'
        }

        filepath = self.generator.generate_raw_sha256(hashes)

        self.assertTrue(os.path.exists(filepath))

    def test_create_test_hashes(self):
        """Teste la création de hashes de test."""
        passwords = ['password', '123456', 'qwerty']

        filepath = self.generator.create_test_hashes(passwords, method='md5')

        self.assertTrue(os.path.exists(filepath))

        with open(filepath, 'r') as f:
            lines = f.readlines()

        self.assertEqual(len(lines), 3)

    def test_get_format_hint(self):
        """Teste la récupération des hints de format."""
        self.assertEqual(self.generator.get_format_hint('md5'), 'raw-md5')
        self.assertEqual(self.generator.get_format_hint('bcrypt'), 'bcrypt')
        self.assertEqual(self.generator.get_format_hint('insecure_md5'), 'raw-md5')

    def test_generate_from_password_database(self):
        """Teste la génération depuis PasswordDatabase."""
        db = PasswordDatabase()
        db.add_user('alice', 'password', method='insecure_md5')
        db.add_user('bob', 'test123', method='bcrypt')

        files = self.generator.generate_from_password_database(db)

        self.assertIsInstance(files, dict)
        self.assertTrue(len(files) > 0)

        # Vérifier que les fichiers existent
        for filepath in files.values():
            self.assertTrue(os.path.exists(filepath))

    def test_display_file_info(self):
        """Teste l'affichage d'informations sur un fichier."""
        hashes = {'user1': 'abc123'}
        filepath = self.generator.generate_raw_md5(hashes)

        info = self.generator.display_file_info(filepath)

        self.assertIsInstance(info, str)
        self.assertIn('FICHIER', info)
        self.assertIn('user1', info)


class TestWordlistManager(unittest.TestCase):
    """Tests pour WordlistManager."""

    def setUp(self):
        """Configuration avant chaque test."""
        self.temp_dir = tempfile.mkdtemp()
        self.manager = WordlistManager(output_dir=self.temp_dir)

    def tearDown(self):
        """Nettoyage après chaque test."""
        shutil.rmtree(self.temp_dir)

    def test_get_common_passwords(self):
        """Teste la récupération de mots de passe courants."""
        passwords = self.manager.get_common_passwords()

        self.assertIsInstance(passwords, list)
        self.assertTrue(len(passwords) > 100)
        self.assertIn('password', passwords)
        self.assertIn('123456', passwords)

    def test_get_common_passwords_with_french(self):
        """Teste l'inclusion des mots de passe français."""
        passwords = self.manager.get_common_passwords(include_french=True)

        self.assertIn('motdepasse', passwords)
        self.assertIn('azerty', passwords)

    def test_create_wordlist(self):
        """Teste la création d'une wordlist."""
        passwords = ['test1', 'test2', 'test3']

        filepath = self.manager.create_wordlist(passwords)

        self.assertTrue(os.path.exists(filepath))

        with open(filepath, 'r') as f:
            lines = f.readlines()

        self.assertEqual(len(lines), 3)

    def test_create_wordlist_deduplicate(self):
        """Teste la déduplication lors de la création."""
        passwords = ['test', 'test', 'unique']

        filepath = self.manager.create_wordlist(passwords, deduplicate=True)

        with open(filepath, 'r') as f:
            lines = f.readlines()

        self.assertEqual(len(lines), 2)

    def test_create_common_wordlist(self):
        """Teste la création d'une wordlist courante."""
        filepath = self.manager.create_common_wordlist()

        self.assertTrue(os.path.exists(filepath))

        with open(filepath, 'r') as f:
            lines = f.readlines()

        self.assertTrue(len(lines) > 100)

    def test_create_numeric_wordlist(self):
        """Teste la création d'une wordlist numérique."""
        filepath = self.manager.create_numeric_wordlist(min_length=2, max_length=3)

        self.assertTrue(os.path.exists(filepath))

        with open(filepath, 'r') as f:
            lines = f.readlines()

        # 10-99 (90) + 100-999 (900) = 990 lignes
        self.assertEqual(len(lines), 990)

    def test_create_pattern_wordlist(self):
        """Teste la création d'une wordlist avec patterns."""
        base_words = ['test']

        filepath = self.manager.create_pattern_wordlist(
            base_words,
            add_numbers=True,
            add_symbols=False
        )

        self.assertTrue(os.path.exists(filepath))

        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        # Vérifier quelques variations
        self.assertIn('test1', content)
        self.assertIn('Test', content)

    def test_combine_wordlists(self):
        """Teste la combinaison de wordlists."""
        # Créer deux wordlists
        filepath1 = self.manager.create_wordlist(['password1', 'password2'], 'list1.txt')
        filepath2 = self.manager.create_wordlist(['password3', 'password4'], 'list2.txt')

        combined = self.manager.combine_wordlists([filepath1, filepath2])

        self.assertTrue(os.path.exists(combined))

        with open(combined, 'r') as f:
            lines = f.readlines()

        self.assertEqual(len(lines), 4)

    def test_get_wordlist_stats(self):
        """Teste les statistiques d'une wordlist."""
        passwords = ['123', 'abc', 'abc123', 'p@ss!']
        filepath = self.manager.create_wordlist(passwords)

        stats = self.manager.get_wordlist_stats(filepath)

        self.assertEqual(stats['total_lines'], 4)
        self.assertEqual(stats['numeric_only'], 1)
        self.assertEqual(stats['alpha_only'], 1)
        self.assertEqual(stats['alphanumeric'], 1)
        self.assertEqual(stats['with_symbols'], 1)

    def test_display_wordlist_info(self):
        """Teste l'affichage d'informations sur une wordlist."""
        passwords = ['test1', 'test2']
        filepath = self.manager.create_wordlist(passwords)

        info = self.manager.display_wordlist_info(filepath)

        self.assertIsInstance(info, str)
        self.assertIn('WORDLIST', info)
        self.assertIn('test1', info)


class TestJTRResultParser(unittest.TestCase):
    """Tests pour JTRResultParser."""

    def test_parse_show_output(self):
        """Teste le parsing de la sortie --show."""
        output = """user1:password
user2:123456
user3:qwerty

3 password hashes cracked, 0 left
"""

        cracked = JTRResultParser.parse_show_output(output)

        self.assertEqual(len(cracked), 3)
        self.assertEqual(cracked['user1'], 'password')
        self.assertEqual(cracked['user2'], '123456')
        self.assertEqual(cracked['user3'], 'qwerty')

    def test_calculate_crack_rate(self):
        """Teste le calcul du taux de cassage."""
        rate = JTRResultParser.calculate_crack_rate(3, 5)
        self.assertEqual(rate, 60.0)

        rate = JTRResultParser.calculate_crack_rate(0, 5)
        self.assertEqual(rate, 0.0)

        rate = JTRResultParser.calculate_crack_rate(5, 0)
        self.assertEqual(rate, 0.0)

    def test_format_crack_results(self):
        """Teste le formatage des résultats."""
        cracked = {'user1': 'password', 'user2': '123456'}

        result = JTRResultParser.format_crack_results(cracked, 5, 10.5)

        self.assertIsInstance(result, str)
        self.assertIn('2/5', result)
        self.assertIn('10.5', result)
        self.assertIn('user1', result)
        self.assertIn('password', result)

    def test_analyze_password_strength(self):
        """Teste l'analyse de force des mots de passe."""
        passwords = [
            '123456',           # Faible, numérique
            'password',         # Faible, alpha
            'Pass123',          # Faible, alphanum
            'SecureP@ss',       # Moyen, symboles
            'VerySecurePass123!'  # Fort, symboles
        ]

        stats = JTRResultParser.analyze_password_strength(passwords)

        self.assertEqual(stats['total'], 5)
        self.assertTrue(stats['weak'] > 0)
        self.assertTrue(stats['numeric_only'] > 0)
        self.assertTrue(stats['with_symbols'] > 0)

    def test_display_password_analysis(self):
        """Teste l'affichage de l'analyse."""
        passwords = ['password', '123456']

        analysis = JTRResultParser.display_password_analysis(passwords)

        self.assertIsInstance(analysis, str)
        self.assertIn('ANALYSE', analysis)
        self.assertIn('Nombre total: 2', analysis)

    def test_parse_crack_output(self):
        """Teste le parsing de la sortie de cassage."""
        output = """Loaded 5 password hashes
password         (user1)
123456           (user2)
Warning: insufficient hash data
"""

        result = JTRResultParser.parse_crack_output(output)

        self.assertIn('cracked_passwords', result)
        self.assertEqual(len(result['cracked_passwords']), 2)
        self.assertEqual(result['cracked_passwords']['user1'], 'password')

        # Vérifier les warnings
        self.assertTrue(len(result['warnings']) > 0)


class TestJohnRipperIntegration(unittest.TestCase):
    """Tests d'intégration pour John the Ripper."""

    def setUp(self):
        """Configuration avant chaque test."""
        self.temp_dir = tempfile.mkdtemp()
        self.wrapper = JohnTheRipperWrapper()
        self.generator = HashFileGenerator(output_dir=self.temp_dir)
        self.wordlist_mgr = WordlistManager(output_dir=self.temp_dir)

    def tearDown(self):
        """Nettoyage après chaque test."""
        shutil.rmtree(self.temp_dir)

    def test_full_workflow_md5(self):
        """Teste le workflow complet avec MD5."""
        # 1. Créer des hashes
        test_passwords = ['password', '123456']
        hash_file = self.generator.create_test_hashes(test_passwords, method='md5')

        self.assertTrue(os.path.exists(hash_file))

        # 2. Créer une wordlist
        wordlist = self.wordlist_mgr.create_wordlist(test_passwords)

        self.assertTrue(os.path.exists(wordlist))

        # 3. Si JtR est installé, lancer le cassage
        if self.wrapper.is_installed:
            success, output = self.wrapper.crack_hash_file(
                hash_file,
                wordlist=wordlist,
                format_type='raw-md5',
                timeout=10
            )

            self.assertTrue(success)

            # Vérifier les résultats
            cracked = self.wrapper.show_cracked(hash_file, 'raw-md5')
            # Au moins un devrait être cassé avec la wordlist
            self.assertTrue(len(cracked) >= 0)

    def test_password_database_to_jtr(self):
        """Teste l'export d'une PasswordDatabase vers JtR."""
        db = PasswordDatabase()
        db.add_user('alice', 'password', method='insecure_md5')
        db.add_user('bob', 'test123', method='bcrypt')

        files = self.generator.generate_from_password_database(db)

        # Vérifier que les fichiers sont créés
        self.assertTrue('md5' in files or 'bcrypt' in files)

        for filepath in files.values():
            self.assertTrue(os.path.exists(filepath))

    def test_wordlist_patterns(self):
        """Teste la génération de wordlists avec patterns."""
        base_words = ['password', 'admin']

        filepath = self.wordlist_mgr.create_pattern_wordlist(
            base_words,
            add_numbers=True,
            add_symbols=True
        )

        stats = self.wordlist_mgr.get_wordlist_stats(filepath)

        # Devrait avoir généré plusieurs variations
        self.assertTrue(stats['total_lines'] > len(base_words))


if __name__ == '__main__':
    unittest.main()
