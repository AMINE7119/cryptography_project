"""
Démonstration des algorithmes de hachage modernes et de la sécurité des mots de passe.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.hashing.hash_algorithms import HashEngine
from src.hashing.salt_pepper import SaltGenerator, RainbowTableSimulator
from src.hashing.password_manager import PasswordDatabase


def demo_hash_comparison():
    """Démontre les différents algorithmes de hachage."""
    print("=" * 80)
    print("DÉMONSTRATION 1: COMPARAISON DES ALGORITHMES DE HACHAGE")
    print("=" * 80)

    engine = HashEngine()

    # Comparer les hashes
    password = "SecurePassword123!"
    print(engine.compare_hashes(password))

    print("\n[Appuyez sur Entrée pour continuer...]")
    input()


def demo_collision_resistance():
    """Démontre la résistance aux collisions."""
    print("\n\n")
    print("=" * 80)
    print("DÉMONSTRATION 2: RÉSISTANCE AUX COLLISIONS (Effet Avalanche)")
    print("=" * 80)

    engine = HashEngine()

    # Changement d'un seul caractère
    text1 = "password"
    text2 = "Password"  # Juste une majuscule différente

    print(engine.demonstrate_collision_resistance(text1, text2))

    print("\n[Appuyez sur Entrée pour continuer...]")
    input()


def demo_salt_importance():
    """Démontre l'importance des salts."""
    print("\n\n")
    print("=" * 80)
    print("DÉMONSTRATION 3: POURQUOI LES SALTS SONT CRUCIAUX")
    print("=" * 80)

    salt_gen = SaltGenerator()
    print(salt_gen.demonstrate_salt_importance())

    print("\n[Appuyez sur Entrée pour continuer...]")
    input()


def demo_hashing_methods():
    """Compare différentes méthodes de hachage."""
    print("\n\n")
    print("=" * 80)
    print("DÉMONSTRATION 4: COMPARAISON DES MÉTHODES")
    print("=" * 80)

    salt_gen = SaltGenerator()
    print(salt_gen.compare_hashing_methods())

    print("\n[Appuyez sur Entrée pour continuer...]")
    input()


def demo_rainbow_tables():
    """Démontre les attaques par rainbow tables."""
    print("\n\n")
    print("=" * 80)
    print("DÉMONSTRATION 5: ATTAQUES PAR RAINBOW TABLES")
    print("=" * 80)

    simulator = RainbowTableSimulator()
    print(simulator.demonstrate_rainbow_table_attack())

    print("\n[Appuyez sur Entrée pour continuer...]")
    input()


def demo_password_database():
    """Démontre une base de données de mots de passe sécurisée."""
    print("\n\n")
    print("=" * 80)
    print("DÉMONSTRATION 6: BASE DE DONNÉES DE MOTS DE PASSE")
    print("=" * 80)

    # Créer la base de données
    db = PasswordDatabase()

    print("\nCréation d'utilisateurs avec différentes méthodes...")

    # Ajouter des utilisateurs avec différentes méthodes
    db.add_user("alice", "password123", method='insecure_md5')
    print("  ✓ Alice ajoutée (MD5 - INSECURE)")

    db.add_user("bob", "SecureP@ss456", method='sha256_salt')
    print("  ✓ Bob ajouté (SHA-256 + Salt)")

    db.add_user("charlie", "MyPassword789!", method='pbkdf2')
    print("  ✓ Charlie ajouté (PBKDF2)")

    db.add_user("diana", "Str0ng!Pass", method='bcrypt')
    print("  ✓ Diana ajoutée (bcrypt)")

    print("\n" + "=" * 80)
    print("Test de connexion:")
    print("=" * 80)

    # Tester la connexion
    success, msg = db.login("alice", "password123")
    print(f"Alice avec bon mot de passe: {msg}")

    success, msg = db.login("alice", "wrongpassword")
    print(f"Alice avec mauvais mot de passe: {msg}")

    success, msg = db.login("diana", "Str0ng!Pass")
    print(f"Diana avec bon mot de passe: {msg}")

    print("\n" + "=" * 80)
    print("Analyse de sécurité:")
    print("=" * 80)
    print(db.analyze_security())

    print("\n" + "=" * 80)
    print("Simulation de violation de base de données:")
    print("=" * 80)
    print(db.demonstrate_database_breach())

    print("\n[Appuyez sur Entrée pour continuer...]")
    input()


def demo_performance_benchmark():
    """Compare les performances des algorithmes."""
    print("\n\n")
    print("=" * 80)
    print("DÉMONSTRATION 7: BENCHMARK DE PERFORMANCE")
    print("=" * 80)

    engine = HashEngine()

    print("\nBenchmark en cours (1000 hachages pour chaque algorithme)...")
    results = engine.benchmark_algorithms(iterations=1000)

    print("\nRÉSULTATS:")
    print("-" * 80)
    print(f"{'Algorithme':<15} | {'Temps (s)':<12} | {'Hash/sec':<15} | Notes")
    print("-" * 80)

    for algo, time_taken in sorted(results.items(), key=lambda x: x[1]):
        hashes_per_sec = 1000 / time_taken if time_taken > 0 else float('inf')

        if algo == 'MD5':
            note = "Rapide mais CASSÉ"
        elif algo == 'SHA-1':
            note = "Rapide mais DÉPRÉCIÉ"
        elif algo == 'SHA-256':
            note = "Bon équilibre"
        elif algo == 'SHA-512':
            note = "Plus lent mais plus sûr"
        elif algo == 'bcrypt':
            note = "Intentionnellement LENT (bon!)"
        else:
            note = ""

        print(f"{algo:<15} | {time_taken:11.4f}s | {hashes_per_sec:14.0f} | {note}")

    print("-" * 80)
    print("\nOBSERVATION:")
    print("  bcrypt est ~1000x plus lent que MD5/SHA-256")
    print("  → C'est VOULU! Ralentit les attaques par force brute")
    print("  → Un attaquant doit attendre ~0.1s par tentative au lieu de 0.0001s")
    print("  → Pour 1M de tentatives: 27h vs 1.7 minutes!")
    print("=" * 80)

    print("\n[Appuyez sur Entrée pour continuer...]")
    input()


def demo_classical_vs_modern():
    """Compare la cryptographie classique et moderne."""
    print("\n\n")
    print("=" * 80)
    print("DÉMONSTRATION 8: CLASSIQUE vs MODERNE")
    print("=" * 80)

    output = []

    output.append("\n┌─────────────────────────────────────────────────────────────────────┐")
    output.append("│              CRYPTOGRAPHIE CLASSIQUE vs MODERNE                     │")
    output.append("└─────────────────────────────────────────────────────────────────────┘")

    output.append("\n" + "=" * 80)
    output.append("CHIFFREMENT CLASSIQUE (César, Vigenère, Playfair)")
    output.append("=" * 80)
    output.append("  Objectif:      Transformer le texte pour le rendre illisible")
    output.append("  Réversible:    OUI (avec la clé)")
    output.append("  Utilisation:   Messages secrets")
    output.append("  Sécurité:      FAIBLE (cassable en secondes)")
    output.append("  Époque:        Antiquité → Début 20ème siècle")
    output.append("")
    output.append("  Exemple:")
    output.append("    Entrée:  'HELLO'")
    output.append("    Clé:     3 (César)")
    output.append("    Sortie:  'KHOOR'")
    output.append("    Inverse: 'KHOOR' → 'HELLO' (avec clé)")

    output.append("\n" + "=" * 80)
    output.append("HACHAGE MODERNE (MD5, SHA-256, bcrypt)")
    output.append("=" * 80)
    output.append("  Objectif:      Créer une empreinte unique des données")
    output.append("  Réversible:    NON (fonction à sens unique)")
    output.append("  Utilisation:   Stockage de mots de passe, intégrité")
    output.append("  Sécurité:      ÉLEVÉE (impossible à inverser)")
    output.append("  Époque:        1990s → Aujourd'hui")
    output.append("")
    output.append("  Exemple:")
    output.append("    Entrée:  'HELLO'")
    output.append("    SHA-256: '185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969'")
    output.append("    Inverse: IMPOSSIBLE (par design!)")

    output.append("\n" + "=" * 80)
    output.append("DIFFÉRENCES CLÉS")
    output.append("=" * 80)

    comparison = [
        ("Aspect", "Chiffrement Classique", "Hachage Moderne"),
        ("-" * 20, "-" * 25, "-" * 25),
        ("Réversibilité", "Réversible avec clé", "Irréversible"),
        ("Longueur sortie", "Même que l'entrée", "Fixe (256 bits, etc.)"),
        ("Même entrée", "Même sortie (avec même clé)", "TOUJOURS même hash"),
        ("Petit changement", "Petit changement sortie", "Hash complètement différent"),
        ("Utilisation", "Communication secrète", "Vérification, stockage"),
        ("Clé requise", "OUI", "NON"),
        ("Sécurité 2025", "OBSOLÈTE", "MODERNE")
    ]

    for row in comparison:
        output.append(f"  {row[0]:<20} | {row[1]:<25} | {row[2]:<25}")

    output.append("\n" + "=" * 80)
    output.append("QUAND UTILISER QUOI?")
    output.append("=" * 80)
    output.append("  Chiffrement (AES, RSA - pas César!):")
    output.append("    ✓ Envoyer un message secret")
    output.append("    ✓ Stocker des données confidentielles")
    output.append("    ✓ Communication sécurisée (HTTPS)")
    output.append("")
    output.append("  Hachage (SHA-256, bcrypt):")
    output.append("    ✓ Stocker des mots de passe")
    output.append("    ✓ Vérifier l'intégrité de fichiers")
    output.append("    ✓ Signatures numériques")
    output.append("    ✓ Blockchain, cryptocurrencies")
    output.append("=" * 80)

    print('\n'.join(output))

    print("\n[Appuyez sur Entrée pour continuer...]")
    input()


def main():
    """Exécute toutes les démonstrations."""
    print("\n")
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 25 + "HACHAGE MODERNE - DÉMO" + " " * 31 + "║")
    print("║" + " " * 18 + "De la cryptographie classique au moderne" + " " * 19 + "║")
    print("╚" + "═" * 78 + "╝")

    try:
        demo_hash_comparison()
        demo_collision_resistance()
        demo_salt_importance()
        demo_hashing_methods()
        demo_rainbow_tables()
        demo_password_database()
        demo_performance_benchmark()
        demo_classical_vs_modern()

        print("\n\n")
        print("╔" + "═" * 78 + "╗")
        print("║" + " " * 30 + "DÉMO TERMINÉE" + " " * 35 + "║")
        print("║" + " " * 78 + "║")
        print("║  Vous avez vu l'évolution de la cryptographie:                              ║")
        print("║    Phase 1: Chiffrement classique (César, Vigenère, Playfair)               ║")
        print("║    Phase 2: Cryptanalyse (comment les casser)                               ║")
        print("║    Phase 3: Hachage moderne (stockage sécurisé de mots de passe)            ║")
        print("║" + " " * 78 + "║")
        print("║  Prochaine étape: Phase 4 - John the Ripper (cassage de hashes)             ║")
        print("╚" + "═" * 78 + "╝")

    except KeyboardInterrupt:
        print("\n\nDémo interrompue par l'utilisateur.")
    except Exception as e:
        print(f"\n\nErreur: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
