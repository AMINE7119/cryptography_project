"""
Casseur de chiffrement de Vigenère utilisant l'examen de Kasiski,
l'indice de coïncidence et l'analyse de fréquence.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from algorithms.vigenere import VigenereCipher
from algorithms.caesar import CaesarCipher
from .frequency_analysis import FrequencyAnalyzer
from typing import List, Tuple, Dict
from collections import Counter


class VigenereBreaker:
    """Classe pour casser le chiffrement de Vigenère."""

    def __init__(self, language='french'):
        """
        Initialise le casseur de Vigenère.

        Args:
            language (str): 'french' ou 'english'
        """
        self.cipher = VigenereCipher()
        self.caesar_cipher = CaesarCipher()
        self.analyzer = FrequencyAnalyzer(language=language)
        self.language = language

    def kasiski_examination(self, ciphertext: str, min_seq_length: int = 3) -> List[int]:
        """
        Utilise l'examen de Kasiski pour estimer la longueur de la clé.

        Principe: Les répétitions dans le texte chiffré indiquent des répétitions
        dans le texte original chiffrées avec la même partie de la clé.

        Args:
            ciphertext (str): Le texte chiffré
            min_seq_length (int): Longueur minimale des séquences à chercher

        Returns:
            list: Longueurs de clés probables (triées par probabilité)
        """
        # Trouver les séquences répétées
        sequences = self.analyzer.find_repeating_sequences(ciphertext, min_seq_length)

        # Calculer les espacements entre répétitions
        spacings = []
        for seq, positions in sequences.items():
            if len(positions) >= 2:
                for i in range(len(positions) - 1):
                    spacing = positions[i+1] - positions[i]
                    spacings.append(spacing)

        if not spacings:
            return []

        # Trouver les facteurs communs des espacements
        factors = self.analyzer.find_common_factors(spacings)

        # Compter la fréquence de chaque facteur possible
        factor_counts = Counter()
        for spacing in spacings:
            for factor in range(2, min(spacing + 1, 21)):  # Limite à 20
                if spacing % factor == 0:
                    factor_counts[factor] += 1

        # Retourner les facteurs les plus communs
        common_factors = [factor for factor, count in factor_counts.most_common(10)]

        return common_factors if common_factors else list(range(2, 11))

    def index_of_coincidence_attack(self, ciphertext: str, max_key_length: int = 20) -> List[int]:
        """
        Utilise l'indice de coïncidence pour déterminer la longueur de la clé.

        Principe: Pour la bonne longueur de clé, chaque sous-séquence aura
        un IC proche de 0.065 (texte en clair). Pour une mauvaise longueur,
        l'IC sera proche de 0.038 (aléatoire).

        Args:
            ciphertext (str): Le texte chiffré
            max_key_length (int): Longueur maximale de clé à tester

        Returns:
            list: Longueurs de clés probables (triées par score IC)
        """
        clean_text = ''.join(c.upper() for c in ciphertext if c.isalpha())
        ic_scores = []

        for key_length in range(1, min(max_key_length + 1, len(clean_text) // 2)):
            # Diviser le texte en sous-séquences
            subsequences = [''] * key_length

            for i, char in enumerate(clean_text):
                subsequences[i % key_length] += char

            # Calculer l'IC moyen pour cette longueur de clé
            avg_ic = sum(self.analyzer.index_of_coincidence(subseq)
                        for subseq in subsequences) / key_length

            # L'IC devrait être proche de 0.065 pour la bonne longueur
            # Plus proche de 0.065, meilleur le score
            score = abs(avg_ic - 0.065)
            ic_scores.append((key_length, avg_ic, score))

        # Trier par score (plus bas = meilleur)
        ic_scores.sort(key=lambda x: x[2])

        # Retourner les longueurs de clés probables
        return [length for length, ic, score in ic_scores[:5]]

    def determine_key_length(self, ciphertext: str) -> int:
        """
        Détermine la longueur de la clé en combinant Kasiski et IC.

        Args:
            ciphertext (str): Le texte chiffré

        Returns:
            int: Longueur de clé la plus probable
        """
        # Méthode 1: Kasiski
        kasiski_lengths = self.kasiski_examination(ciphertext)

        # Méthode 2: Index de coïncidence
        ic_lengths = self.index_of_coincidence_attack(ciphertext)

        # Trouver les longueurs communes aux deux méthodes
        common_lengths = set(kasiski_lengths[:5]) & set(ic_lengths[:5])

        if common_lengths:
            # Retourner la plus petite longueur commune
            return min(common_lengths)
        elif ic_lengths:
            # Sinon, utiliser l'IC (plus fiable)
            return ic_lengths[0]
        elif kasiski_lengths:
            # Ou Kasiski si IC a échoué
            return kasiski_lengths[0]
        else:
            # Défaut
            return 3

    def break_substitution_cipher(self, ciphertext: str, key_length: int) -> str:
        """
        Casse le chiffrement en traitant chaque position de clé comme un César.

        Args:
            ciphertext (str): Le texte chiffré
            key_length (int): Longueur de la clé

        Returns:
            str: Clé trouvée
        """
        clean_text = ''.join(c.upper() for c in ciphertext if c.isalpha())
        key_chars = []

        # Pour chaque position dans la clé
        for position in range(key_length):
            # Extraire tous les caractères chiffrés avec cette position de clé
            subsequence = ''
            for i in range(position, len(clean_text), key_length):
                subsequence += clean_text[i]

            # Utiliser l'analyse de fréquence pour trouver le décalage
            # Supposer que 'E' est la lettre la plus fréquente
            most_common = self.analyzer.get_most_common_letters(subsequence, n=1)

            if most_common:
                most_common_letter = most_common[0][0]
                # En français/anglais, 'E' est généralement la plus fréquente
                expected_letter = 'E'

                # Le décalage est la différence
                shift = (ord(most_common_letter) - ord(expected_letter)) % 26

                # La lettre de la clé est celle qui produit ce décalage
                key_char = chr(ord('A') + shift)
                key_chars.append(key_char)
            else:
                key_chars.append('A')  # Défaut

        return ''.join(key_chars)

    def refine_key(self, ciphertext: str, initial_key: str) -> str:
        """
        Affine la clé trouvée en testant des variations.

        Args:
            ciphertext (str): Le texte chiffré
            initial_key (str): Clé initiale à affiner

        Returns:
            str: Clé affinée
        """
        best_key = initial_key
        best_score = self.analyzer.chi_squared_score(
            self.cipher.decrypt(ciphertext, initial_key)
        )

        # Pour chaque position de la clé
        for i in range(len(initial_key)):
            # Essayer de modifier cette lettre
            for shift in [-2, -1, 1, 2]:  # Variations de ±2
                test_key_chars = list(initial_key)
                new_char_code = (ord(initial_key[i]) - ord('A') + shift) % 26
                test_key_chars[i] = chr(ord('A') + new_char_code)
                test_key = ''.join(test_key_chars)

                # Tester cette variation
                try:
                    decrypted = self.cipher.decrypt(ciphertext, test_key)
                    score = self.analyzer.chi_squared_score(decrypted)

                    if score < best_score:
                        best_key = test_key
                        best_score = score
                except Exception:
                    continue

        return best_key

    def auto_break(self, ciphertext: str, max_key_length: int = 20) -> Tuple[str, str, float]:
        """
        Casse automatiquement le chiffrement de Vigenère.

        Args:
            ciphertext (str): Le texte chiffré
            max_key_length (int): Longueur maximale de clé à considérer

        Returns:
            tuple: (clé trouvée, texte déchiffré, score de confiance)
        """
        # Étape 1: Déterminer la longueur de la clé
        key_length = self.determine_key_length(ciphertext)

        # Limiter la longueur de clé
        if key_length > max_key_length:
            key_length = max_key_length

        # Étape 2: Trouver la clé
        initial_key = self.break_substitution_cipher(ciphertext, key_length)

        # Étape 3: Affiner la clé
        refined_key = self.refine_key(ciphertext, initial_key)

        # Étape 4: Déchiffrer
        try:
            plaintext = self.cipher.decrypt(ciphertext, refined_key)
            score = self.analyzer.chi_squared_score(plaintext)
            return (refined_key, plaintext, score)
        except Exception as e:
            return (refined_key, f"Erreur: {str(e)}", float('inf'))

    def try_multiple_key_lengths(self, ciphertext: str, lengths: List[int] = None) -> List[Tuple[int, str, str, float]]:
        """
        Essaie plusieurs longueurs de clés et retourne les meilleurs résultats.

        Args:
            ciphertext (str): Le texte chiffré
            lengths (list): Longueurs spécifiques à essayer (None = auto)

        Returns:
            list: Liste de tuples (longueur clé, clé, texte, score)
        """
        if lengths is None:
            # Utiliser Kasiski et IC
            kasiski = self.kasiski_examination(ciphertext)
            ic = self.index_of_coincidence_attack(ciphertext)
            lengths = list(set(kasiski[:3] + ic[:3]))

        results = []

        for length in lengths:
            key = self.break_substitution_cipher(ciphertext, length)
            key = self.refine_key(ciphertext, key)

            try:
                plaintext = self.cipher.decrypt(ciphertext, key)
                score = self.analyzer.chi_squared_score(plaintext)
                results.append((length, key, plaintext, score))
            except Exception:
                continue

        # Trier par score
        results.sort(key=lambda x: x[3])

        return results

    def display_analysis(self, ciphertext: str, show_details: bool = True) -> str:
        """
        Affiche une analyse complète du chiffrement de Vigenère.

        Args:
            ciphertext (str): Le texte chiffré
            show_details (bool): Afficher les détails de l'analyse

        Returns:
            str: Rapport d'analyse formaté
        """
        output = []
        output.append("=" * 70)
        output.append("CRYPTANALYSE DU CHIFFREMENT DE VIGENÈRE")
        output.append("=" * 70)
        output.append(f"Texte chiffré: {ciphertext[:50]}{'...' if len(ciphertext) > 50 else ''}")
        output.append(f"Longueur: {len([c for c in ciphertext if c.isalpha()])} lettres")
        output.append("=" * 70)
        output.append("")

        # Analyse initiale
        ic = self.analyzer.index_of_coincidence(ciphertext)
        output.append(f"Indice de coïncidence global: {ic:.4f}")

        if ic > 0.06:
            output.append("→ IC élevé: Probablement monoalphabétique (César) ou texte court")
        else:
            output.append("→ IC faible: Confirme un chiffrement polyalphabétique (Vigenère)")
        output.append("")

        if show_details:
            # Examen de Kasiski
            output.append("EXAMEN DE KASISKI:")
            kasiski_lengths = self.kasiski_examination(ciphertext)
            output.append(f"Longueurs de clés probables: {kasiski_lengths[:5]}")
            output.append("")

            # Indice de coïncidence
            output.append("ANALYSE PAR INDICE DE COÏNCIDENCE:")
            ic_lengths = self.index_of_coincidence_attack(ciphertext)
            output.append(f"Longueurs de clés probables: {ic_lengths[:5]}")
            output.append("")

        # Détermination de la longueur
        key_length = self.determine_key_length(ciphertext)
        output.append(f"LONGUEUR DE CLÉ DÉTECTÉE: {key_length}")
        output.append("=" * 70)
        output.append("")

        # Cassage
        output.append("TENTATIVE DE CASSAGE:")
        output.append("-" * 70)

        key, plaintext, score = self.auto_break(ciphertext)

        output.append(f"Clé trouvée: {key}")
        output.append(f"Score chi-carré: {score:.2f}")
        output.append(f"Confiance: {self._confidence_level(score)}")
        output.append("")
        output.append(f"Texte déchiffré:")
        output.append(f"{plaintext[:200]}{'...' if len(plaintext) > 200 else ''}")
        output.append("")
        output.append("=" * 70)

        # Essayer d'autres longueurs si le score n'est pas bon
        if score > 100:
            output.append("TENTATIVES AVEC D'AUTRES LONGUEURS DE CLÉS:")
            output.append("-" * 70)

            results = self.try_multiple_key_lengths(ciphertext)[:3]
            for i, (length, alt_key, alt_text, alt_score) in enumerate(results, 1):
                output.append(f"\n#{i} - Longueur: {length} | Clé: {alt_key} | Score: {alt_score:.2f}")
                output.append(f"Texte: {alt_text[:80]}...")

            output.append("\n" + "=" * 70)

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
        elif chi_squared_score < 500:
            return "FAIBLE ✗"
        else:
            return "TRÈS FAIBLE ✗✗"
