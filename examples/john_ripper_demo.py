"""
Démonstration de l'intégration John the Ripper.

Ce script montre comment utiliser le module john_ripper pour casser des mots de passe.
"""

import sys
import os
import time

# Ajouter le répertoire parent au path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.john_ripper.jtr_wrapper import JohnTheRipperWrapper
from src.john_ripper.hash_file_generator import HashFileGenerator
from src.john_ripper.wordlist_manager import WordlistManager
from src.john_ripper.result_parser import JTRResultParser
from src.hashing.password_manager import PasswordDatabase


def print_header(title):
    """Affiche un en-tête formaté."""
    print("\n" + "="*80)
    print(title.center(80))
    print("="*80)


def demo_1_installation_check():
    """Démo 1: Vérification de l'installation de JtR."""
    print_header("DÉMO 1: VÉRIFICATION DE L'INSTALLATION")

    wrapper = JohnTheRipperWrapper()

    print(f"\nJohn the Ripper installé: {wrapper.is_installed}")

    if wrapper.is_installed:
        version = wrapper.get_version()
        print(f"Version: {version}")

        print("\nQuelques formats supportés:")
        formats = wrapper.list_formats()
        for fmt in formats[:10]:
            print(f"  - {fmt}")

        print(f"\n... et {len(formats) - 10} autres formats")

    else:
        print("\n⚠ John the Ripper n'est pas installé.")
        print("\nPour installer:")
        print("  Ubuntu/Debian: sudo apt-get install john")
        print("  macOS:         brew install john")
        print("  Windows:       Télécharger depuis https://www.openwall.com/john/")


def demo_2_hash_file_generation():
    """Démo 2: Génération de fichiers de hashes."""
    print_header("DÉMO 2: GÉNÉRATION DE FICHIERS DE HASHES")

    generator = HashFileGenerator()

    # Créer des hashes MD5 de test
    print("\n1. Création de hashes MD5 (faciles à casser):")
    test_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']

    hash_file = generator.create_test_hashes(test_passwords, method='md5')

    print(f"\nFichier créé: {hash_file}")
    print(generator.display_file_info(hash_file))

    # Créer depuis une base de données
    print("\n2. Création depuis une base de données:")

    db = PasswordDatabase()
    db.add_user("alice", "password123", method='insecure_md5')
    db.add_user("bob", "qwerty", method='insecure_md5')
    db.add_user("charlie", "SecureP@ss456", method='bcrypt')

    files = generator.generate_from_password_db(db, 'database_hashes')

    print(f"\n{len(files)} fichiers générés:")
    for method, filepath in files.items():
        print(f"\n{method.upper()}:")
        print(f"  Fichier: {filepath}")

        # Compter les lignes
        with open(filepath, 'r') as f:
            lines = len(f.readlines())
        print(f"  Nombre de hashes: {lines}")


def demo_3_wordlist_creation():
    """Démo 3: Création de wordlists."""
    print_header("DÉMO 3: CRÉATION DE WORDLISTS")

    manager = WordlistManager()

    # 1. Wordlist commune
    print("\n1. Wordlist de mots de passe courants:")

    wordlist = manager.create_common_wordlist('common_passwords.txt')
    stats = manager.get_wordlist_stats(wordlist)

    print(f"\nFichier: {wordlist}")
    print(f"Nombre de mots de passe: {stats['total_lines']}")
    print(f"Mots de passe uniques: {stats['unique_passwords']}")

    # 2. Wordlist avec patterns
    print("\n2. Wordlist avec patterns (variations):")

    base_words = ['password', 'admin', 'user']
    pattern_wordlist = manager.create_pattern_wordlist(
        base_words,
        add_numbers=True,
        add_symbols=True,
        filename='pattern_wordlist.txt'
    )

    stats = manager.get_wordlist_stats(pattern_wordlist)

    print(f"\nFichier: {pattern_wordlist}")
    print(f"Nombre de variations: {stats['total_lines']}")
    print(f"À partir de {len(base_words)} mots de base")

    print("\nExemples de variations générées:")
    with open(pattern_wordlist, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            if i >= 10:
                break
            print(f"  - {line.strip()}")

    # 3. Wordlist numérique courte
    print("\n3. Wordlist numérique (codes PIN 4 chiffres):")

    numeric_wordlist = manager.create_numeric_wordlist(
        min_length=4,
        max_length=4,
        filename='pins_4digits.txt'
    )

    stats = manager.get_wordlist_stats(numeric_wordlist)

    print(f"\nFichier: {numeric_wordlist}")
    print(f"Nombre de combinaisons: {stats['total_lines']} (0000-9999)")


def demo_4_result_parsing():
    """Démo 4: Analyse des résultats."""
    print_header("DÉMO 4: ANALYSE DES RÉSULTATS")

    parser = JTRResultParser()

    # Simuler des résultats de cassage
    print("\n1. Analyse de mots de passe cassés:")

    cracked_passwords = {
        'user1': 'password',
        'user2': '123456',
        'user3': 'qwerty',
        'user4': 'admin',
        'user5': 'letmein'
    }

    print(parser.format_crack_results(cracked_passwords, total_hashes=10, time_taken=5.2))

    print("\n2. Analyse de force des mots de passe:")

    passwords_list = list(cracked_passwords.values())
    print(parser.display_password_analysis(passwords_list))


def demo_5_full_attack_simulation():
    """Démo 5: Simulation d'attaque complète."""
    print_header("DÉMO 5: SIMULATION D'ATTAQUE COMPLÈTE")

    wrapper = JohnTheRipperWrapper()
    generator = HashFileGenerator()
    wordlist_mgr = WordlistManager()
    parser = JTRResultParser()

    # Étape 1: Créer une base de données vulnérable
    print("\nÉTAPE 1: Création d'une base de données vulnérable")
    print("-"*80)

    db = PasswordDatabase()
    vulnerable_passwords = {
        'alice': 'password',
        'bob': '123456',
        'charlie': 'qwerty',
        'diana': 'admin',
        'eve': 'letmein'
    }

    for username, password in vulnerable_passwords.items():
        db.add_user(username, password, method='insecure_md5')

    print("✅ Base de données créée avec 5 utilisateurs (MD5, AUCUN SALT)")

    # Étape 2: Exporter les hashes
    print("\nÉTAPE 2: Export des hashes")
    print("-"*80)

    files = generator.generate_from_password_db(db, 'vulnerable_db')
    hash_file = files.get('md5')

    print(f"✅ Hashes exportés: {hash_file}")

    # Étape 3: Créer une wordlist
    print("\nÉTAPE 3: Création d'une wordlist")
    print("-"*80)

    wordlist = wordlist_mgr.create_common_wordlist('attack_wordlist.txt')

    print(f"✅ Wordlist créée: {wordlist}")

    stats = wordlist_mgr.get_wordlist_stats(wordlist)
    print(f"   Contient {stats['total_lines']} mots de passe courants")

    # Étape 4: Lancer l'attaque (si JtR est installé)
    if wrapper.is_installed:
        print("\nÉTAPE 4: Lancement de l'attaque John the Ripper")
        print("-"*80)

        print("\n🔓 Cassage en cours...")

        start_time = time.time()

        success, output = wrapper.crack_hash_file(
            hash_file,
            wordlist=wordlist,
            format_type='raw-md5',
            timeout=30
        )

        time_taken = time.time() - start_time

        if success:
            # Récupérer les résultats
            cracked = wrapper.show_cracked(hash_file, 'raw-md5')

            print(f"\n✅ Attaque terminée en {time_taken:.2f} secondes!")

            print("\n" + "="*80)
            print("RÉSULTATS")
            print("="*80)

            print(parser.format_crack_results(cracked, 5, time_taken))

            if cracked:
                print(parser.display_password_analysis(list(cracked.values())))

                # Analyse de sécurité
                print("\n" + "="*80)
                print("ANALYSE DE SÉCURITÉ")
                print("="*80)

                print(f"\n✓ Mots de passe cassés: {len(cracked)}/5 ({len(cracked)/5*100:.0f}%)")
                print(f"✓ Temps moyen par hash: {time_taken/5:.2f}s")
                print(f"✓ Vitesse: {5/time_taken:.1f} hashes/seconde")

                print("\n⚠ VULNÉRABILITÉS DÉTECTÉES:")
                print("  → MD5 est OBSOLÈTE et CASSABLE en quelques secondes")
                print("  → Absence de salt permet les rainbow table attacks")
                print("  → Mots de passe trop courants et faibles")

                print("\n✓ RECOMMANDATIONS:")
                print("  → Migrer vers bcrypt (rounds=12 minimum)")
                print("  → Utiliser un salt unique par utilisateur")
                print("  → Imposer des politiques de mots de passe forts")
                print("  → Activer l'authentification multi-facteurs (2FA)")

        else:
            print(f"\n❌ Erreur: {output}")

    else:
        print("\nÉTAPE 4: Simulation (JtR non installé)")
        print("-"*80)

        print("\n📊 PRÉDICTION:")
        print("Si John the Ripper était installé, voici ce qui se passerait:")
        print(f"  → Temps estimé: < 1 seconde")
        print(f"  → Mots de passe cassés: 5/5 (100%)")
        print(f"  → Raison: MD5 sans salt + wordlist contient tous les mots de passe")

        print("\n💡 COMPARAISON:")
        print("  MD5 (actuel):        ~5,000,000,000 hash/sec sur GPU")
        print("  bcrypt (recommandé):         ~20 hash/sec")
        print(f"  → bcrypt est {5_000_000_000 / 20:,.0f}x plus lent (VOULU!)")

        print("\n🎓 LEÇON:")
        print("  La lenteur intentionnelle de bcrypt protège contre les attaques")
        print("  par force brute, rendant le cassage pratiquement impossible.")


def demo_6_benchmark():
    """Démo 6: Benchmark de John the Ripper."""
    print_header("DÉMO 6: BENCHMARK DE JOHN THE RIPPER")

    wrapper = JohnTheRipperWrapper()

    if not wrapper.is_installed:
        print("\n⚠ John the Ripper n'est pas installé.")
        print("Cette démonstration nécessite JtR.")
        return

    print("\n🔥 Lancement du benchmark...")
    print("Cela peut prendre 30-60 secondes...\n")

    benchmarks = wrapper.benchmark()

    if benchmarks:
        print("="*80)
        print("RÉSULTATS DU BENCHMARK")
        print("="*80)

        print(f"\n{'Format':<30} | {'Vitesse (hashes/sec)':<20} | {'Commentaire':<20}")
        print("-"*80)

        # Trier par vitesse (du plus rapide au plus lent)
        sorted_benchmarks = sorted(benchmarks.items(), key=lambda x: x[1], reverse=True)

        for format_name, speed in sorted_benchmarks[:20]:
            # Ajouter un commentaire basé sur la vitesse
            if speed > 10_000_000:
                comment = "⚠ TRÈS RAPIDE (danger)"
            elif speed > 1_000_000:
                comment = "⚠ Rapide"
            elif speed > 100_000:
                comment = "△ Moyen"
            else:
                comment = "✓ Lent (sécurisé)"

            print(f"{format_name:<30} | {speed:>18,} | {comment:<20}")

        print("="*80)

        print("\n💡 OBSERVATION:")
        print("  → Les formats les plus rapides (MD5, SHA-1) sont les moins sécurisés")
        print("  → Les formats lents (bcrypt, scrypt) sont conçus pour résister aux attaques")
        print("  → Un GPU moderne peut tester des milliards de MD5 par seconde!")

    else:
        print("❌ Impossible de récupérer les résultats du benchmark.")


def demo_7_comparison_classical_vs_modern():
    """Démo 7: Comparaison cryptographie classique vs moderne."""
    print_header("DÉMO 7: CRYPTOGRAPHIE CLASSIQUE VS MODERNE")

    print("\n" + "="*80)
    print("COMPARAISON: CHIFFREMENT vs HACHAGE")
    print("="*80)

    print("""
┌─────────────────────────────────────────────────────────────────────────────┐
│ CHIFFREMENT CLASSIQUE (César, Vigenère, Playfair)                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ But:           Communication secrète                                        │
│ Réversible:    OUI (avec la clé)                                           │
│ Clé:           Nécessaire pour chiffrer/déchiffrer                         │
│ Sécurité:      FAIBLE (cassable en < 3 secondes)                           │
│ Cas d'usage:   Éducation, histoire de la crypto                            │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ HACHAGE MODERNE (MD5, SHA, bcrypt)                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│ But:           Stockage sécurisé de mots de passe                          │
│ Réversible:    NON (fonction à sens unique)                                │
│ Clé:           Aucune (utilise salt/pepper)                                │
│ Sécurité:      Variable (bcrypt > SHA > MD5)                               │
│ Cas d'usage:   Authentification, intégrité                                 │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ CASSAGE AVEC JOHN THE RIPPER                                               │
├─────────────────────────────────────────────────────────────────────────────┤
│ César:         Inutile (force brute directe en < 0.01s)                    │
│ Vigenère:      Inutile (cryptanalyse statistique en < 3s)                  │
│ MD5:           TRÈS EFFICACE (milliards de hash/sec)                       │
│ SHA-256:       Efficace (millions de hash/sec)                             │
│ bcrypt:        Difficile (~20 hash/sec, intentionnel)                      │
└─────────────────────────────────────────────────────────────────────────────┘
""")

    print("\n🎓 ÉVOLUTION DE LA CRYPTOGRAPHIE:")
    print("""
  1940s:  Chiffrement classique (Enigma, etc.)
          → Cassé par cryptanalyse statistique

  1990s:  Hachage simple (MD5)
          → Cassé par rainbow tables et GPU

  2000s:  Hachage avec salt (SHA + salt)
          → Ralentit mais pas suffisant contre GPU

  2010s+: Hachage adaptatif (bcrypt, scrypt, Argon2)
          → Résiste aux attaques modernes grâce à la lenteur intentionnelle
""")


def main():
    """Fonction principale."""
    print_header("DÉMONSTRATIONS JOHN THE RIPPER")

    print("\nCe script contient 7 démonstrations:")
    print("  1. Vérification de l'installation")
    print("  2. Génération de fichiers de hashes")
    print("  3. Création de wordlists")
    print("  4. Analyse des résultats")
    print("  5. Simulation d'attaque complète")
    print("  6. Benchmark de JtR")
    print("  7. Comparaison classique vs moderne")

    print("\n" + "="*80)

    # Lancer toutes les démos
    demo_1_installation_check()

    input("\nAppuyez sur Entrée pour continuer...")
    demo_2_hash_file_generation()

    input("\nAppuyez sur Entrée pour continuer...")
    demo_3_wordlist_creation()

    input("\nAppuyez sur Entrée pour continuer...")
    demo_4_result_parsing()

    input("\nAppuyez sur Entrée pour continuer...")
    demo_5_full_attack_simulation()

    input("\nAppuyez sur Entrée pour continuer...")
    demo_6_benchmark()

    input("\nAppuyez sur Entrée pour continuer...")
    demo_7_comparison_classical_vs_modern()

    print_header("FIN DES DÉMONSTRATIONS")

    print("\n✓ Toutes les démonstrations sont terminées!")
    print("\n💡 Pour en savoir plus:")
    print("  - Lancez le CLI: python src/interface/cli.py")
    print("  - Option 6: John the Ripper")


if __name__ == "__main__":
    main()
