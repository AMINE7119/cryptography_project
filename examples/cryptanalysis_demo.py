"""
Démonstration des capacités de cryptanalyse.
Ce script montre comment casser les chiffrements classiques.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.algorithms.caesar import CaesarCipher
from src.algorithms.vigenere import VigenereCipher
from src.cryptanalysis.caesar_breaker import CaesarBreaker
from src.cryptanalysis.vigenere_breaker import VigenereBreaker
from src.cryptanalysis.frequency_analysis import FrequencyAnalyzer


def demo_caesar_breaking():
    """Démonstration du cassage de César."""
    print("=" * 80)
    print("DÉMONSTRATION: Cassage du Chiffrement de César")
    print("=" * 80)

    # 1. Créer un message chiffré
    cipher = CaesarCipher()
    plaintext = "LECRYPTOGRAPHIEESTLASCIENCEDUSECRETQUIPERMETDEPROTEGERLESMESSAGES"
    key = 7

    print(f"\n1. CHIFFREMENT:")
    print(f"   Texte original: {plaintext}")
    print(f"   Clé secrète: {key}")

    ciphertext = cipher.encrypt(plaintext, key)
    print(f"   Texte chiffré: {ciphertext}")

    # 2. Casser le chiffrement (sans connaître la clé)
    print(f"\n2. CRYPTANALYSE:")
    print(f"   Supposons que nous interceptons: {ciphertext}")
    print(f"   Nous ne connaissons PAS la clé...")

    breaker = CaesarBreaker()

    # Méthode 1: Force brute
    print(f"\n   Méthode 1: FORCE BRUTE (essayer toutes les clés)")
    results = breaker.auto_break(ciphertext, top_n=3)

    print(f"\n   Top 3 résultats:")
    for i, (found_key, decrypted, score) in enumerate(results, 1):
        print(f"   #{i} - Clé {found_key} (score: {score:.2f})")
        print(f"       → {decrypted[:60]}...")

    # 3. Vérification
    print(f"\n3. RÉSULTAT:")
    best_key, best_text, best_score = results[0]
    if best_key == key:
        print(f"   ✓ SUCCÈS! Clé trouvée: {best_key}")
        print(f"   ✓ Temps de cassage: < 1 seconde")
        print(f"   ✓ Texte déchiffré: {best_text}")
    else:
        print(f"   Meilleure correspondance avec clé {best_key}")

    print("\n" + "=" * 80)


def demo_vigenere_breaking():
    """Démonstration du cassage de Vigenère."""
    print("\n\n")
    print("=" * 80)
    print("DÉMONSTRATION: Cassage du Chiffrement de Vigenère")
    print("=" * 80)

    # 1. Créer un message chiffré
    cipher = VigenereCipher()
    plaintext = "LACRYPTOGRAPHIEESTLASCIENCEDUSECRETQUIPERMETDEPROTEGERLESMESSAGESET" \
                "LESDONNEESCONTRELESATTAQUESMALVEILLANTESELLEUTILISEDESALGORITHMES" \
                "MATHEMATIQUESCOMPLEXESPOURGARANTIRLASECURITEDESINFORMATIONS"
    key = "PYTHON"

    print(f"\n1. CHIFFREMENT:")
    print(f"   Texte original: {plaintext[:80]}...")
    print(f"   Clé secrète: {key}")

    ciphertext = cipher.encrypt(plaintext, key)
    print(f"   Texte chiffré: {ciphertext[:80]}...")

    # 2. Analyse préliminaire
    print(f"\n2. ANALYSE PRÉLIMINAIRE:")
    analyzer = FrequencyAnalyzer()
    ic = analyzer.index_of_coincidence(ciphertext)
    print(f"   Indice de coïncidence: {ic:.4f}")

    if ic > 0.06:
        print(f"   → Probablement monoalphabétique (César)")
    else:
        print(f"   → Probablement polyalphabétique (Vigenère)")

    # 3. Cryptanalyse
    print(f"\n3. CRYPTANALYSE:")
    print(f"   Utilisation de l'examen de Kasiski et de l'indice de coïncidence...")

    breaker = VigenereBreaker()

    # Déterminer la longueur de clé
    key_length = breaker.determine_key_length(ciphertext)
    print(f"   Longueur de clé détectée: {key_length}")

    # Casser
    print(f"   Cassage en cours...")
    found_key, decrypted, score = breaker.auto_break(ciphertext)

    # 4. Résultats
    print(f"\n4. RÉSULTAT:")
    print(f"   Clé originale: {key}")
    print(f"   Clé trouvée:   {found_key}")

    if found_key == key:
        print(f"   ✓ SUCCÈS PARFAIT!")
    elif len(found_key) == len(key):
        # Comparer caractère par caractère
        matches = sum(1 for i in range(len(key)) if found_key[i] == key[i])
        accuracy = (matches / len(key)) * 100
        print(f"   ✓ Clé partiellement trouvée ({accuracy:.0f}% correcte)")

    print(f"\n   Score de confiance: {score:.2f}")
    print(f"   Texte déchiffré: {decrypted[:100]}...")

    print("\n" + "=" * 80)


def demo_frequency_analysis():
    """Démonstration de l'analyse de fréquence."""
    print("\n\n")
    print("=" * 80)
    print("DÉMONSTRATION: Analyse de Fréquence")
    print("=" * 80)

    # Comparer texte en clair vs texte chiffré
    plaintext = "LACRYPTOGRAPHIEESTUNDOMAINEFASCINANTQUICOMBINELES" \
                "MATHEMATIQUESLINFORMATIQUEETLASECURITE"

    cipher = VigenereCipher()
    ciphertext = cipher.encrypt(plaintext, "SECRET")

    analyzer = FrequencyAnalyzer()

    print("\n1. TEXTE EN CLAIR:")
    print(f"   {plaintext}")
    print(f"\n   Indice de coïncidence: {analyzer.index_of_coincidence(plaintext):.4f}")
    print(f"   (Attendu pour du français: ~0.065)")

    most_common_plain = analyzer.get_most_common_letters(plaintext, n=5)
    print(f"   Lettres les plus fréquentes: {', '.join([f'{l}({c})' for l, c in most_common_plain])}")

    print("\n2. TEXTE CHIFFRÉ (Vigenère):")
    print(f"   {ciphertext}")
    print(f"\n   Indice de coïncidence: {analyzer.index_of_coincidence(ciphertext):.4f}")
    print(f"   (Plus bas = polyalphabétique)")

    most_common_cipher = analyzer.get_most_common_letters(ciphertext, n=5)
    print(f"   Lettres les plus fréquentes: {', '.join([f'{l}({c})' for l, c in most_common_cipher])}")

    print("\n3. CONCLUSION:")
    print(f"   Le chiffrement de Vigenère 'aplatit' la distribution des fréquences,")
    print(f"   rendant l'analyse de fréquence simple inefficace.")
    print(f"   C'est pourquoi il était considéré 'indéchiffrable' pendant des siècles!")

    print("\n" + "=" * 80)


def demo_security_comparison():
    """Comparaison de la sécurité César vs Vigenère."""
    print("\n\n")
    print("=" * 80)
    print("COMPARAISON DE SÉCURITÉ: César vs Vigenère")
    print("=" * 80)

    import time

    # Test César
    print("\n1. CHIFFREMENT DE CÉSAR:")
    plaintext = "MESSAGESECRETETIMPORTANT" * 3

    caesar_cipher = CaesarCipher()
    caesar_ciphertext = caesar_cipher.encrypt(plaintext, 13)

    print(f"   Espace des clés: 25 clés possibles")
    print(f"   Méthode de cassage: Force brute")

    caesar_breaker = CaesarBreaker()
    start_time = time.time()
    results = caesar_breaker.brute_force(caesar_ciphertext)
    caesar_time = time.time() - start_time

    print(f"   Temps de cassage: {caesar_time:.4f} secondes")
    print(f"   Sécurité: ✗ TRÈS FAIBLE")

    # Test Vigenère
    print("\n2. CHIFFREMENT DE VIGENÈRE:")
    vigenere_cipher = VigenereCipher()
    vigenere_ciphertext = vigenere_cipher.encrypt(plaintext, "CLESECRETETRESLONGUE")

    key_space = 26 ** 20  # Pour une clé de 20 caractères
    print(f"   Espace des clés: ~{key_space:.2e} clés possibles")
    print(f"   Méthode de cassage: Kasiski + IC + Fréquence")

    vigenere_breaker = VigenereBreaker()
    start_time = time.time()
    found_key, decrypted, score = vigenere_breaker.auto_break(vigenere_ciphertext)
    vigenere_time = time.time() - start_time

    print(f"   Temps de cassage: {vigenere_time:.4f} secondes")
    print(f"   Sécurité: ✓ MOYENNE (pour texte long)")

    # Comparaison
    print("\n3. CONCLUSION:")
    print(f"   César est {(vigenere_time / caesar_time):.1f}x plus facile à casser que Vigenère")
    print(f"   Mais les deux sont vulnérables à l'analyse cryptographique!")
    print(f"   Pour une vraie sécurité → utiliser AES, RSA, etc.")

    print("\n" + "=" * 80)


def main():
    """Exécute toutes les démonstrations."""
    print("\n")
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 20 + "CRYPTANALYSE CLASSIQUE - DÉMO" + " " * 29 + "║")
    print("║" + " " * 15 + "Démonstration du cassage de chiffrements" + " " * 22 + "║")
    print("╚" + "═" * 78 + "╝")

    try:
        demo_caesar_breaking()
        input("\n[Appuyez sur Entrée pour continuer...]")

        demo_vigenere_breaking()
        input("\n[Appuyez sur Entrée pour continuer...]")

        demo_frequency_analysis()
        input("\n[Appuyez sur Entrée pour continuer...]")

        demo_security_comparison()

        print("\n\n")
        print("╔" + "═" * 78 + "╗")
        print("║" + " " * 30 + "DÉMO TERMINÉE" + " " * 35 + "║")
        print("║" + " " * 78 + "║")
        print("║  Vous avez vu comment les chiffrements classiques peuvent être cassés       ║")
        print("║  en quelques secondes avec les bonnes techniques!                           ║")
        print("║" + " " * 78 + "║")
        print("║  Essayez maintenant l'interface CLI ou GUI pour vos propres tests.          ║")
        print("╚" + "═" * 78 + "╝")

    except KeyboardInterrupt:
        print("\n\nDémo interrompue par l'utilisateur.")
    except Exception as e:
        print(f"\n\nErreur: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
