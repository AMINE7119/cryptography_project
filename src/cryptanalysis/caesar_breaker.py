"""
Casseur de chiffrement de César par force brute et analyse de fréquence.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from algorithms.caesar import CaesarCipher
from .frequency_analysis import FrequencyAnalyzer
from typing import List, Tuple


class CaesarBreaker:
    """Classe pour casser le chiffrement de César."""

    def __init__(self, language='french'):
        """
        Initialise le casseur de César.

        Args:
            language (str): 'french' ou 'english'
        """
        self.cipher = CaesarCipher()
        self.analyzer = FrequencyAnalyzer(language=language)
        self.language = language

    def brute_force(self, ciphertext: str) -> List[Tuple[int, str, float]]:
        """
        Essaie toutes les clés possibles (0-25) et retourne tous les résultats.

        Args:
            ciphertext (str): Le texte chiffré

        Returns:
            list: Liste de tuples (clé, texte déchiffré, score chi-carré)
                  Triée par score (meilleur score en premier)
        """
        results = []

        # Essayer chaque clé possible
        for key in range(26):
            try:
                decrypted = self.cipher.decrypt(ciphertext, key)
                score = self.analyzer.chi_squared_score(decrypted)
                results.append((key, decrypted, score))
            except Exception:
                continue

        # Trier par score chi-carré (plus bas = meilleur)
        results.sort(key=lambda x: x[2])

        return results

    def auto_break(self, ciphertext: str, top_n: int = 3) -> List[Tuple[int, str, float]]:
        """
        Casse automatiquement le chiffrement et retourne les n meilleures solutions.

        Args:
            ciphertext (str): Le texte chiffré
            top_n (int): Nombre de solutions à retourner

        Returns:
            list: Liste des n meilleures solutions (clé, texte, score)
        """
        all_results = self.brute_force(ciphertext)
        return all_results[:top_n]

    def break_with_known_word(self, ciphertext: str, known_word: str) -> List[Tuple[int, str]]:
        """
        Casse le chiffrement en cherchant un mot connu dans le texte déchiffré.

        Args:
            ciphertext (str): Le texte chiffré
            known_word (str): Un mot qu'on sait être dans le texte original

        Returns:
            list: Liste de tuples (clé, texte déchiffré) contenant le mot
        """
        results = []
        known_word_upper = known_word.upper()

        for key in range(26):
            try:
                decrypted = self.cipher.decrypt(ciphertext, key)
                if known_word_upper in decrypted.upper():
                    results.append((key, decrypted))
            except Exception:
                continue

        return results

    def frequency_attack(self, ciphertext: str) -> Tuple[int, str]:
        """
        Casse le chiffrement en utilisant l'analyse de fréquence.
        Suppose que la lettre la plus fréquente est 'E' en français ou en anglais.

        Args:
            ciphertext (str): Le texte chiffré

        Returns:
            tuple: (clé trouvée, texte déchiffré)
        """
        # Trouver la lettre la plus fréquente
        most_common = self.analyzer.get_most_common_letters(ciphertext, n=1)

        if not most_common:
            return (0, "Texte trop court pour l'analyse de fréquence")

        most_common_letter = most_common[0][0]

        # En français et anglais, 'E' est généralement la plus fréquente
        expected_most_common = 'E'

        # Calculer le décalage
        # Si la lettre la plus fréquente est 'H', et on attend 'E', décalage = H - E = 3
        shift = (ord(most_common_letter) - ord(expected_most_common)) % 26

        # Déchiffrer avec ce décalage
        decrypted = self.cipher.decrypt(ciphertext, shift)

        return (shift, decrypted)

    def display_analysis(self, ciphertext: str, top_n: int = 5) -> str:
        """
        Affiche une analyse complète avec les meilleures solutions.

        Args:
            ciphertext (str): Le texte chiffré
            top_n (int): Nombre de solutions à afficher

        Returns:
            str: Rapport d'analyse formaté
        """
        output = []
        output.append("=" * 70)
        output.append("CRYPTANALYSE DU CHIFFREMENT DE CÉSAR")
        output.append("=" * 70)
        output.append(f"Texte chiffré: {ciphertext[:50]}{'...' if len(ciphertext) > 50 else ''}")
        output.append(f"Longueur: {len([c for c in ciphertext if c.isalpha()])} lettres")
        output.append("=" * 70)
        output.append("")

        # Analyse de fréquence du texte chiffré
        output.append("ANALYSE DE FRÉQUENCE DU TEXTE CHIFFRÉ:")
        most_common = self.analyzer.get_most_common_letters(ciphertext, n=5)
        output.append(f"Lettres les plus fréquentes: {', '.join([f'{letter}({count})' for letter, count in most_common])}")
        output.append("")

        # Force brute - top résultats
        output.append(f"TOP {top_n} SOLUTIONS (par score chi-carré):")
        output.append("-" * 70)

        results = self.auto_break(ciphertext, top_n=top_n)

        for i, (key, plaintext, score) in enumerate(results, 1):
            output.append(f"\n#{i} - Clé: {key} | Score: {score:.2f}")
            output.append(f"Texte: {plaintext[:60]}{'...' if len(plaintext) > 60 else ''}")

        output.append("")
        output.append("=" * 70)
        output.append("RECOMMANDATION:")
        if results:
            best_key, best_text, best_score = results[0]
            output.append(f"La clé la plus probable est: {best_key}")
            output.append(f"Score de confiance: {self._confidence_level(best_score)}")
        output.append("=" * 70)

        return '\n'.join(output)

    def _confidence_level(self, chi_squared_score: float) -> str:
        """
        Détermine le niveau de confiance basé sur le score chi-carré.

        Args:
            chi_squared_score (float): Score chi-carré

        Returns:
            str: Niveau de confiance
        """
        if chi_squared_score < 50:
            return "TRÈS ÉLEVÉE ✓✓✓"
        elif chi_squared_score < 100:
            return "ÉLEVÉE ✓✓"
        elif chi_squared_score < 200:
            return "MOYENNE ✓"
        else:
            return "FAIBLE ✗"

    def interactive_break(self, ciphertext: str):
        """
        Mode interactif pour casser le chiffrement.
        Permet à l'utilisateur de voir différentes solutions et de choisir.

        Args:
            ciphertext (str): Le texte chiffré
        """
        print(self.display_analysis(ciphertext, top_n=5))
        print("\nVoulez-vous voir toutes les 26 possibilités? (o/n): ", end='')

        # Note: Cette fonction est pour usage CLI interactif
        # Dans une GUI, cela serait géré différemment
