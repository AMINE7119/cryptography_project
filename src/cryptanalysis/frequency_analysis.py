"""
Analyse de fréquence pour la cryptanalyse des chiffrements classiques.
"""

from collections import Counter
from typing import Dict, List, Tuple
import math


class FrequencyAnalyzer:
    """Classe pour l'analyse de fréquence des textes chiffrés."""

    # Fréquences des lettres en français (%)
    FRENCH_FREQUENCIES = {
        'E': 14.715, 'A': 7.636, 'I': 7.529, 'S': 7.948, 'N': 7.095,
        'R': 6.553, 'T': 7.244, 'O': 5.796, 'L': 5.456, 'U': 6.311,
        'D': 3.669, 'C': 3.260, 'M': 2.968, 'P': 3.021, 'G': 1.066,
        'B': 1.181, 'V': 1.628, 'H': 0.737, 'F': 1.066, 'Q': 1.362,
        'Y': 0.128, 'X': 0.427, 'J': 0.613, 'K': 0.049, 'W': 0.114,
        'Z': 0.326
    }

    # Fréquences des lettres en anglais (%)
    ENGLISH_FREQUENCIES = {
        'E': 12.702, 'T': 9.056, 'A': 8.167, 'O': 7.507, 'I': 6.966,
        'N': 6.749, 'S': 6.327, 'H': 6.094, 'R': 5.987, 'D': 4.253,
        'L': 4.025, 'C': 2.782, 'U': 2.758, 'M': 2.406, 'W': 2.360,
        'F': 2.228, 'G': 2.015, 'Y': 1.974, 'P': 1.929, 'B': 1.492,
        'V': 0.978, 'K': 0.772, 'J': 0.153, 'X': 0.150, 'Q': 0.095,
        'Z': 0.074
    }

    def __init__(self, language='french'):
        """
        Initialise l'analyseur de fréquence.

        Args:
            language (str): 'french' ou 'english'
        """
        self.language = language
        self.expected_frequencies = (self.FRENCH_FREQUENCIES if language == 'french'
                                     else self.ENGLISH_FREQUENCIES)

    def count_letters(self, text: str) -> Dict[str, int]:
        """
        Compte la fréquence de chaque lettre dans le texte.

        Args:
            text (str): Le texte à analyser

        Returns:
            dict: Dictionnaire {lettre: nombre d'occurrences}
        """
        # Nettoyer le texte (majuscules, lettres uniquement)
        clean_text = ''.join(c.upper() for c in text if c.isalpha())
        return dict(Counter(clean_text))

    def calculate_frequencies(self, text: str) -> Dict[str, float]:
        """
        Calcule les fréquences en pourcentage de chaque lettre.

        Args:
            text (str): Le texte à analyser

        Returns:
            dict: Dictionnaire {lettre: fréquence en %}
        """
        letter_counts = self.count_letters(text)
        total_letters = sum(letter_counts.values())

        if total_letters == 0:
            return {}

        frequencies = {}
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            count = letter_counts.get(letter, 0)
            frequencies[letter] = (count / total_letters) * 100

        return frequencies

    def get_most_common_letters(self, text: str, n: int = 5) -> List[Tuple[str, int]]:
        """
        Retourne les n lettres les plus fréquentes.

        Args:
            text (str): Le texte à analyser
            n (int): Nombre de lettres à retourner

        Returns:
            list: Liste de tuples (lettre, nombre d'occurrences)
        """
        letter_counts = self.count_letters(text)
        return Counter(letter_counts).most_common(n)

    def chi_squared_score(self, text: str) -> float:
        """
        Calcule le score chi-carré pour comparer avec les fréquences attendues.
        Plus le score est bas, plus le texte ressemble à la langue attendue.

        Args:
            text (str): Le texte à analyser

        Returns:
            float: Score chi-carré
        """
        observed_frequencies = self.calculate_frequencies(text)
        chi_squared = 0.0

        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            observed = observed_frequencies.get(letter, 0)
            expected = self.expected_frequencies.get(letter, 0)

            if expected > 0:
                chi_squared += ((observed - expected) ** 2) / expected

        return chi_squared

    def index_of_coincidence(self, text: str) -> float:
        """
        Calcule l'indice de coïncidence (IC) du texte.

        L'IC mesure la probabilité que deux lettres prises au hasard soient identiques.
        - IC ≈ 0.065 pour un texte en français/anglais
        - IC ≈ 0.038 pour un texte aléatoire

        Args:
            text (str): Le texte à analyser

        Returns:
            float: Indice de coïncidence
        """
        letter_counts = self.count_letters(text)
        total_letters = sum(letter_counts.values())

        if total_letters <= 1:
            return 0.0

        # Formule IC = Σ(ni * (ni-1)) / (N * (N-1))
        ic_sum = sum(count * (count - 1) for count in letter_counts.values())
        ic = ic_sum / (total_letters * (total_letters - 1))

        return ic

    def find_repeating_sequences(self, text: str, min_length: int = 3) -> Dict[str, List[int]]:
        """
        Trouve les séquences répétées dans le texte et leurs positions.
        Utile pour l'examen de Kasiski.

        Args:
            text (str): Le texte à analyser
            min_length (int): Longueur minimale des séquences

        Returns:
            dict: {séquence: [positions]}
        """
        clean_text = ''.join(c.upper() for c in text if c.isalpha())
        sequences = {}

        # Chercher des séquences de différentes longueurs
        for length in range(min_length, min(20, len(clean_text) // 2)):
            for i in range(len(clean_text) - length + 1):
                seq = clean_text[i:i+length]

                # Chercher d'autres occurrences de cette séquence
                positions = []
                for j in range(len(clean_text) - length + 1):
                    if clean_text[j:j+length] == seq:
                        positions.append(j)

                # Si la séquence apparaît au moins 2 fois
                if len(positions) >= 2:
                    sequences[seq] = positions

        return sequences

    def calculate_gcd(self, a: int, b: int) -> int:
        """
        Calcule le plus grand commun diviseur (PGCD).

        Args:
            a (int): Premier nombre
            b (int): Deuxième nombre

        Returns:
            int: PGCD de a et b
        """
        while b:
            a, b = b, a % b
        return a

    def find_common_factors(self, numbers: List[int]) -> List[int]:
        """
        Trouve les facteurs communs d'une liste de nombres.

        Args:
            numbers (list): Liste de nombres

        Returns:
            list: Liste des facteurs communs triés
        """
        if not numbers:
            return []

        # Calculer le PGCD de tous les nombres
        result = numbers[0]
        for num in numbers[1:]:
            result = self.calculate_gcd(result, num)

        # Trouver tous les diviseurs du PGCD
        factors = []
        for i in range(2, result + 1):
            if result % i == 0:
                factors.append(i)

        return sorted(factors)

    def display_frequency_chart(self, text: str, show_expected: bool = True) -> str:
        """
        Génère un affichage visuel des fréquences de lettres.

        Args:
            text (str): Le texte à analyser
            show_expected (bool): Afficher les fréquences attendues

        Returns:
            str: Graphique des fréquences
        """
        observed_freq = self.calculate_frequencies(text)

        output = ["=" * 60]
        output.append("ANALYSE DE FRÉQUENCE")
        output.append("=" * 60)
        output.append(f"Langue de référence: {self.language.upper()}")
        output.append(f"Texte analysé: {len([c for c in text if c.isalpha()])} lettres")
        output.append("=" * 60)
        output.append("")
        output.append("Lettre | Observé | Attendu | Barre")
        output.append("-" * 60)

        # Trier par fréquence observée
        sorted_letters = sorted(observed_freq.items(), key=lambda x: x[1], reverse=True)

        for letter, obs_freq in sorted_letters:
            exp_freq = self.expected_frequencies.get(letter, 0)

            # Créer une barre visuelle
            bar_length = int(obs_freq * 3)  # Échelle
            bar = '█' * bar_length

            if show_expected:
                output.append(f"  {letter}    | {obs_freq:5.2f}% | {exp_freq:5.2f}% | {bar}")
            else:
                output.append(f"  {letter}    | {obs_freq:5.2f}% | {bar}")

        output.append("=" * 60)
        output.append(f"Indice de coïncidence: {self.index_of_coincidence(text):.4f}")
        output.append(f"Score chi-carré: {self.chi_squared_score(text):.2f}")
        output.append("=" * 60)

        return '\n'.join(output)
