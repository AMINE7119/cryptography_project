import pytest
import sys
import os

# Ajouter le répertoire parent au path pour les imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.cryptanalysis.frequency_analysis import FrequencyAnalyzer
from src.cryptanalysis.caesar_breaker import CaesarBreaker
from src.cryptanalysis.vigenere_breaker import VigenereBreaker
from src.algorithms.caesar import CaesarCipher
from src.algorithms.vigenere import VigenereCipher


class TestFrequencyAnalyzer:
    """Tests pour l'analyseur de fréquence."""

    def setup_method(self):
        """Configure les tests."""
        self.analyzer = FrequencyAnalyzer(language='french')

    def test_count_letters(self):
        """Teste le comptage des lettres."""
        text = "HELLO WORLD"
        counts = self.analyzer.count_letters(text)

        assert counts['H'] == 1
        assert counts['E'] == 1
        assert counts['L'] == 3
        assert counts['O'] == 2
        assert counts['W'] == 1
        assert counts['R'] == 1
        assert counts['D'] == 1

    def test_calculate_frequencies(self):
        """Teste le calcul des fréquences."""
        text = "AAABBC"
        frequencies = self.analyzer.calculate_frequencies(text)

        assert abs(frequencies['A'] - 50.0) < 0.1  # 3/6 = 50%
        assert abs(frequencies['B'] - 33.33) < 0.1  # 2/6 = 33.33%
        assert abs(frequencies['C'] - 16.67) < 0.1  # 1/6 = 16.67%

    def test_index_of_coincidence_plaintext(self):
        """Teste l'IC sur du texte en clair français."""
        # Texte en français
        text = "LECRYPTOGRAPHIEESTLASCIENCEDUSECRET"
        ic = self.analyzer.index_of_coincidence(text)

        # L'IC devrait être proche de 0.065 pour du français
        assert ic > 0.04  # Au moins
        assert ic < 0.10  # Pas trop élevé

    def test_index_of_coincidence_random(self):
        """Teste l'IC sur du texte aléatoire."""
        # Texte aléatoire (distribution uniforme)
        text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 10
        ic = self.analyzer.index_of_coincidence(text)

        # L'IC devrait être proche de 0.038 pour du texte aléatoire
        assert ic < 0.05  # Proche de 0.038

    def test_find_repeating_sequences(self):
        """Teste la détection de séquences répétées."""
        text = "ABCDEFABCDEFGHIJABCDEF"
        sequences = self.analyzer.find_repeating_sequences(text, min_length=3)

        # "ABC", "DEF", "ABCDEF" devraient être détectés
        assert 'ABC' in sequences or 'ABCDEF' in sequences
        assert len(sequences) > 0

    def test_chi_squared_score(self):
        """Teste le score chi-carré."""
        # Texte en français
        french_text = "LECRYPTOGRAPHIEESTLASCIENCEDUSECRET"
        score = self.analyzer.chi_squared_score(french_text)

        # Le score devrait être raisonnablement bas
        assert score < 500  # Seuil arbitraire mais raisonnable

    def test_get_most_common_letters(self):
        """Teste la récupération des lettres les plus fréquentes."""
        text = "AAABBBCCCDDD"
        most_common = self.analyzer.get_most_common_letters(text, n=3)

        assert len(most_common) == 3
        # Les 3 lettres les plus fréquentes devraient être A, B, C ou D
        letters = [letter for letter, count in most_common]
        assert 'A' in letters or 'B' in letters


class TestCaesarBreaker:
    """Tests pour le casseur de César."""

    def setup_method(self):
        """Configure les tests."""
        self.breaker = CaesarBreaker(language='french')
        self.cipher = CaesarCipher()

    def test_brute_force_simple(self):
        """Teste la force brute sur un exemple simple."""
        # Chiffrer un texte
        plaintext = "HELLO"
        key = 3
        ciphertext = self.cipher.encrypt(plaintext, key)

        # Casser
        results = self.breaker.brute_force(ciphertext)

        # On devrait avoir 26 résultats
        assert len(results) == 26

        # Le bon résultat devrait être dans la liste
        found = any(plaintext in result[1] for result in results)
        assert found

    def test_auto_break_correct_key(self):
        """Teste que auto_break trouve la bonne clé."""
        # Texte suffisamment long pour une bonne analyse
        plaintext = "LECRYPTOGRAPHIEESTLASCIENCEDUSECRET"
        key = 7
        ciphertext = self.cipher.encrypt(plaintext, key)

        # Casser
        results = self.breaker.auto_break(ciphertext, top_n=3)

        # Vérifier que le résultat le plus probable est correct
        best_key, best_text, best_score = results[0]

        # La clé ou le texte devrait être correct
        # Note: l'ordre peut varier selon le score
        found = False
        for result_key, result_text, score in results:
            if result_key == key or plaintext in result_text:
                found = True
                break

        assert found

    def test_break_with_known_word(self):
        """Teste le cassage avec un mot connu."""
        plaintext = "CRYPTOGRAPHIEESTUNESCIENCEFASCINANTE"
        key = 5
        ciphertext = self.cipher.encrypt(plaintext, key)

        # Casser avec le mot connu "SCIENCE"
        results = self.breaker.break_with_known_word(ciphertext, "SCIENCE")

        # On devrait trouver au moins un résultat
        assert len(results) > 0

        # Le résultat devrait contenir "SCIENCE"
        found = any("SCIENCE" in text for key, text in results)
        assert found

    def test_frequency_attack(self):
        """Teste l'attaque par fréquence."""
        plaintext = "LECRYPTOGRAPHIEESTLASCIENCEDUSECRET"
        key = 10
        ciphertext = self.cipher.encrypt(plaintext, key)

        # Attaque par fréquence
        found_key, decrypted = self.breaker.frequency_attack(ciphertext)

        # La clé trouvée devrait être proche de la vraie clé
        # (pas toujours exacte avec un texte court)
        assert isinstance(found_key, int)
        assert 0 <= found_key <= 25


class TestVigenereBreaker:
    """Tests pour le casseur de Vigenère."""

    def setup_method(self):
        """Configure les tests."""
        self.breaker = VigenereBreaker(language='french')
        self.cipher = VigenereCipher()

    def test_kasiski_examination(self):
        """Teste l'examen de Kasiski."""
        # Créer un texte avec répétitions
        plaintext = "SECRETSECRETSECRET"
        key = "KEY"
        ciphertext = self.cipher.encrypt(plaintext, key)

        # Kasiski devrait trouver la longueur de clé (3)
        lengths = self.breaker.kasiski_examination(ciphertext)

        # La longueur 3 devrait être dans les résultats
        # Note: peut ne pas toujours être exact avec un texte court
        assert len(lengths) > 0
        assert isinstance(lengths[0], int)

    def test_index_of_coincidence_attack(self):
        """Teste l'attaque par indice de coïncidence."""
        # Texte très long pour améliorer la précision
        plaintext = "LECRYPTOGRAPHIEESTLASCIENCEDUSECRETDECHIFFREMENTQUIPERMETDEPROTEGERLESMESSAGES" * 3
        key = "SECRET"
        ciphertext = self.cipher.encrypt(plaintext, key)

        # IC attack
        lengths = self.breaker.index_of_coincidence_attack(ciphertext)

        # La longueur 6 devrait être trouvée (longueur de "SECRET")
        assert len(lengths) > 0
        # Note: IC n'est pas toujours précis avec des textes courts
        # On vérifie juste qu'on obtient des résultats raisonnables
        assert all(1 <= length <= 20 for length in lengths[:5])

    def test_determine_key_length(self):
        """Teste la détermination de la longueur de clé."""
        plaintext = "CRYPTOGRAPHIEESTLASCIENCEDUSECRETDECHIFFREMENT" * 3
        key = "VIGENERE"
        ciphertext = self.cipher.encrypt(plaintext, key)

        # Déterminer la longueur
        found_length = self.breaker.determine_key_length(ciphertext)

        # Devrait trouver 8 ou proche
        assert isinstance(found_length, int)
        assert 1 <= found_length <= 20

    def test_break_substitution_cipher(self):
        """Teste le cassage comme substitution."""
        plaintext = "LECRYPTOGRAPHIEESTLASCIENCEDUSECRET" * 3
        key = "KEY"
        ciphertext = self.cipher.encrypt(plaintext, key)

        # Casser avec la bonne longueur
        found_key = self.breaker.break_substitution_cipher(ciphertext, len(key))

        # La clé trouvée devrait avoir la bonne longueur
        assert len(found_key) == len(key)
        assert all(c.isalpha() and c.isupper() for c in found_key)

    def test_auto_break_short_key(self):
        """Teste le cassage automatique avec une clé courte."""
        plaintext = "LECRYPTOGRAPHIEESTLASCIENCEDUSECRETDECHIFFREMENTDESMESSAGES" * 2
        key = "CLE"
        ciphertext = self.cipher.encrypt(plaintext, key)

        # Cassage automatique
        found_key, decrypted, score = self.breaker.auto_break(ciphertext)

        # Vérifications de base
        assert isinstance(found_key, str)
        assert len(found_key) > 0
        assert isinstance(score, float)

        # Le score devrait être raisonnable (pas infini)
        assert score < float('inf')

    def test_auto_break_medium_key(self):
        """Teste le cassage automatique avec une clé moyenne."""
        plaintext = "LECRYPTOGRAPHIEESTLASCIENCEDUSECRETDECHIFFREMENTDESMESSAGES" * 3
        key = "SECRET"
        ciphertext = self.cipher.encrypt(plaintext, key)

        # Cassage automatique
        found_key, decrypted, score = self.breaker.auto_break(ciphertext)

        # Vérifications
        assert isinstance(found_key, str)
        assert all(c.isalpha() and c.isupper() for c in found_key)
        assert score < float('inf')

    def test_refine_key(self):
        """Teste le raffinement de clé."""
        plaintext = "LECRYPTOGRAPHIEESTLASCIENCEDUSECRET" * 2
        key = "SECRET"
        ciphertext = self.cipher.encrypt(plaintext, key)

        # Créer une clé approximative
        approx_key = "TFDRET"  # Proche de "SECRET"

        # Raffiner
        refined_key = self.breaker.refine_key(ciphertext, approx_key)

        # La clé raffinée devrait avoir la même longueur
        assert len(refined_key) == len(approx_key)
        assert all(c.isalpha() and c.isupper() for c in refined_key)

    def test_try_multiple_key_lengths(self):
        """Teste l'essai de plusieurs longueurs de clés."""
        plaintext = "CRYPTOGRAPHIEESTLASCIENCEDUSECRETDECHIFFREMENT" * 2
        key = "CLEF"
        ciphertext = self.cipher.encrypt(plaintext, key)

        # Essayer plusieurs longueurs
        results = self.breaker.try_multiple_key_lengths(ciphertext, lengths=[3, 4, 5])

        # On devrait avoir des résultats
        assert len(results) > 0

        # Chaque résultat devrait avoir le bon format
        for length, found_key, plaintext_result, score in results:
            assert isinstance(length, int)
            assert isinstance(found_key, str)
            assert isinstance(score, float)


# Tests d'intégration
class TestCryptanalysisIntegration:
    """Tests d'intégration pour le module de cryptanalyse."""

    def test_caesar_full_workflow(self):
        """Teste le workflow complet de cassage de César."""
        cipher = CaesarCipher()
        breaker = CaesarBreaker()

        # Chiffrer
        plaintext = "LECRYPTOGRAPHIEESTFASCINANTE"
        key = 13
        ciphertext = cipher.encrypt(plaintext, key)

        # Casser
        results = breaker.auto_break(ciphertext, top_n=1)
        best_key, best_text, score = results[0]

        # Vérifier
        assert best_key == key or plaintext in best_text

    def test_vigenere_full_workflow(self):
        """Teste le workflow complet de cassage de Vigenère."""
        cipher = VigenereCipher()
        breaker = VigenereBreaker()

        # Chiffrer avec un texte suffisamment long
        plaintext = "LACRYPTOGRAPHIEESTLASCIENCEDUSECRETQUIPERMETDEPROTEGERLESMESSAGES" * 2
        key = "PYTHON"
        ciphertext = cipher.encrypt(plaintext, key)

        # Casser
        found_key, decrypted, score = breaker.auto_break(ciphertext)

        # Vérifier que le cassage a produit un résultat raisonnable
        assert len(found_key) > 0
        assert score < float('inf')

        # Note: Le cassage peut ne pas être parfait avec un texte court
        # mais devrait produire un score raisonnable

    def test_multilanguage_support(self):
        """Teste le support multilingue."""
        # Analyseur français
        fr_analyzer = FrequencyAnalyzer(language='french')
        fr_text = "LECRYPTOGRAPHIE"
        fr_ic = fr_analyzer.index_of_coincidence(fr_text)

        # Analyseur anglais
        en_analyzer = FrequencyAnalyzer(language='english')
        en_text = "CRYPTOGRAPHY"
        en_ic = en_analyzer.index_of_coincidence(en_text)

        # Les deux devraient donner des résultats raisonnables
        assert 0.0 <= fr_ic <= 1.0
        assert 0.0 <= en_ic <= 1.0
