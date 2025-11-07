import sys
import os

# Ajouter le répertoire parent au path pour les imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto_engine import CryptoEngine
from utils.validators import InputValidator
from cryptanalysis.caesar_breaker import CaesarBreaker
from cryptanalysis.vigenere_breaker import VigenereBreaker
from cryptanalysis.frequency_analysis import FrequencyAnalyzer
from hashing.hash_algorithms import HashEngine
from hashing.salt_pepper import SaltGenerator, RainbowTableSimulator
from hashing.password_manager import PasswordDatabase
from john_ripper.jtr_wrapper import JohnTheRipperWrapper
from john_ripper.hash_file_generator import HashFileGenerator
from john_ripper.wordlist_manager import WordlistManager
from john_ripper.result_parser import JTRResultParser

class CLI:
    """Interface en ligne de commande pour l'application de cryptographie."""
    
    def __init__(self):
        """Initialise l'interface CLI avec le moteur de cryptographie."""
        self.engine = CryptoEngine()
        self.validator = InputValidator()
        self.caesar_breaker = CaesarBreaker()
        self.vigenere_breaker = VigenereBreaker()
        self.frequency_analyzer = FrequencyAnalyzer()
        self.hash_engine = HashEngine()
        self.salt_gen = SaltGenerator()
        self.rainbow_sim = RainbowTableSimulator()
        self.password_db = PasswordDatabase()
        self.jtr_wrapper = JohnTheRipperWrapper()
        self.hash_gen = HashFileGenerator()
        self.wordlist_mgr = WordlistManager()
        self.result_parser = JTRResultParser()
        
    def display_welcome(self):
        """Affiche le message de bienvenue et les instructions."""
        print("="*50)
        print("OUTIL DE CRYPTOGRAPHIE")
        print("="*50)
        print("Bienvenue dans cet outil de cryptographie!")
        print("Cet outil vous permet de chiffrer et déchiffrer des messages")
        print("en utilisant différents algorithmes classiques.")
        print("="*50)
        
    def display_menu(self):
        """Affiche le menu principal."""
        print("\nMENU PRINCIPAL:")
        print("1. Chiffrer un message")
        print("2. Déchiffrer un message")
        print("3. Cryptanalyse (Casser un chiffrement)")
        print("4. Analyse de fréquence")
        print("5. Hachage moderne (Mots de passe)")
        print("6. John the Ripper (Cassage avancé)")
        print("7. Quitter")
        
    def display_algorithms(self):
        """Affiche la liste des algorithmes disponibles."""
        print("\nALGORITHMES DISPONIBLES:")
        algorithms = self.engine.get_available_algorithms()
        for i, algo in enumerate(algorithms, 1):
            print(f"{i}. {algo}")
        
    def run(self):
        """Exécute l'interface en ligne de commande."""
        self.display_welcome()

        while True:
            self.display_menu()
            choice = input("\nVotre choix (1-7): ")

            if choice == '1':
                self.encrypt_workflow()
            elif choice == '2':
                self.decrypt_workflow()
            elif choice == '3':
                self.cryptanalysis_workflow()
            elif choice == '4':
                self.frequency_analysis_workflow()
            elif choice == '5':
                self.hashing_workflow()
            elif choice == '6':
                self.john_the_ripper_workflow()
            elif choice == '7':
                print("\nMerci d'avoir utilisé cet outil. À bientôt!")
                break
            else:
                print("\nOption invalide. Veuillez réessayer.")
    
    def encrypt_workflow(self):
        """Processus de chiffrement."""
        print("\n--- CHIFFREMENT ---")
        
        # Sélection de l'algorithme
        self.display_algorithms()
        algo_choice = self.get_algorithm_choice()
        if not algo_choice:
            return
        
        # Obtenir le texte à chiffrer
        text = input("\nEntrez le texte à chiffrer: ")
        if not self.validator.validate_text(text):
            print("Texte invalide. Veuillez entrer du texte.")
            return
        
        # Obtenir la clé
        key = self.get_key_for_algorithm(algo_choice)
        if key is None:
            return
        
        # Chiffrer le texte
        try:
            encrypted = self.engine.encrypt(text, algo_choice, key)
            print("\nTEXTE CHIFFRÉ:")
            print(encrypted)
        except Exception as e:
            print(f"Erreur lors du chiffrement: {e}")
    
    def decrypt_workflow(self):
        """Processus de déchiffrement."""
        print("\n--- DÉCHIFFREMENT ---")
        
        # Sélection de l'algorithme
        self.display_algorithms()
        algo_choice = self.get_algorithm_choice()
        if not algo_choice:
            return
        
        # Obtenir le texte à déchiffrer
        text = input("\nEntrez le texte à déchiffrer: ")
        if not self.validator.validate_text(text):
            print("Texte invalide. Veuillez entrer du texte.")
            return
        
        # Obtenir la clé
        key = self.get_key_for_algorithm(algo_choice)
        if key is None:
            return
            
        # Déchiffrer le texte
        try:
            decrypted = self.engine.decrypt(text, algo_choice, key)
            print("\nTEXTE DÉCHIFFRÉ:")
            print(decrypted)
        except Exception as e:
            print(f"Erreur lors du déchiffrement: {e}")
    
    def get_algorithm_choice(self):
        """
        Obtient le choix d'algorithme de l'utilisateur.
        
        Returns:
            str or None: Le nom de l'algorithme choisi ou None si annulé
        """
        algorithms = self.engine.get_available_algorithms()
        while True:
            try:
                choice = int(input("\nSélectionnez un algorithme (1-{}): ".format(len(algorithms))))
                if 1 <= choice <= len(algorithms):
                    return algorithms[choice - 1]
                else:
                    print("Choix invalide. Veuillez réessayer.")
            except ValueError:
                print("Veuillez entrer un nombre.")
    
    def get_key_for_algorithm(self, algorithm):
        """
        Obtient la clé appropriée pour l'algorithme sélectionné.
        
        Args:
            algorithm (str): Nom de l'algorithme
            
        Returns:
            Any or None: La clé formatée ou None si annulée
        """
        if algorithm == "César":
            while True:
                key = input("\nEntrez la clé (décalage 0-25): ")
                if self.validator.validate_caesar_key(key):
                    return int(key)
                else:
                    print("Clé invalide. Veuillez entrer un nombre entre 0 et 25.")
        
        elif algorithm == "Vigenère":
            while True:
                key = input("\nEntrez la clé (mot): ")
                if self.validator.validate_vigenere_key(key):
                    return key
                else:
                    print("Clé invalide. Veuillez entrer un mot composé de lettres.")
        
        elif algorithm == "Playfair":
            while True:
                key = input("\nEntrez la clé (mot ou phrase): ")
                if self.validator.validate_playfair_key(key):
                    return key
                else:
                    print("Clé invalide. Veuillez entrer un mot ou une phrase.")
        
        return None

    def cryptanalysis_workflow(self):
        """Processus de cryptanalyse (cassage de chiffrement)."""
        print("\n--- CRYPTANALYSE ---")
        print("Quel type de chiffrement voulez-vous casser?")
        print("1. César")
        print("2. Vigenère")
        print("3. Détection automatique")

        choice = input("\nVotre choix (1-3): ")

        # Obtenir le texte chiffré
        ciphertext = input("\nEntrez le texte chiffré: ")
        if not self.validator.validate_text(ciphertext):
            print("Texte invalide. Veuillez entrer du texte.")
            return

        if choice == '1':
            self._break_caesar(ciphertext)
        elif choice == '2':
            self._break_vigenere(ciphertext)
        elif choice == '3':
            self._auto_detect_and_break(ciphertext)
        else:
            print("Option invalide.")

    def _break_caesar(self, ciphertext: str):
        """Casse un chiffrement de César."""
        print("\nAnalyse en cours...")
        print(self.caesar_breaker.display_analysis(ciphertext, top_n=5))

        # Demander si l'utilisateur veut voir toutes les possibilités
        show_all = input("\nVoulez-vous voir toutes les 26 possibilités? (o/n): ")
        if show_all.lower() == 'o':
            results = self.caesar_breaker.brute_force(ciphertext)
            print("\n" + "=" * 70)
            print("TOUTES LES POSSIBILITÉS:")
            print("=" * 70)
            for key, plaintext, score in results:
                print(f"\nClé {key:2d} | Score: {score:6.2f} | {plaintext[:50]}")

    def _break_vigenere(self, ciphertext: str):
        """Casse un chiffrement de Vigenère."""
        print("\nAnalyse en cours (cela peut prendre quelques secondes)...")

        # Demander si l'utilisateur veut les détails
        show_details = input("Afficher les détails de l'analyse? (o/n): ")
        details = show_details.lower() == 'o'

        print(self.vigenere_breaker.display_analysis(ciphertext, show_details=details))

        # Proposer d'essayer d'autres longueurs
        try_more = input("\nVoulez-vous essayer manuellement une longueur de clé? (o/n): ")
        if try_more.lower() == 'o':
            length = int(input("Entrez la longueur de clé à essayer: "))
            key = self.vigenere_breaker.break_substitution_cipher(ciphertext, length)
            key = self.vigenere_breaker.refine_key(ciphertext, key)
            plaintext = self.vigenere_breaker.cipher.decrypt(ciphertext, key)
            print(f"\nClé trouvée: {key}")
            print(f"Texte déchiffré: {plaintext}")

    def _auto_detect_and_break(self, ciphertext: str):
        """Détecte automatiquement le type de chiffrement et le casse."""
        print("\nDétection automatique en cours...")

        # Utiliser l'indice de coïncidence pour détecter le type
        ic = self.frequency_analyzer.index_of_coincidence(ciphertext)

        print(f"Indice de coïncidence: {ic:.4f}")

        if ic > 0.06:
            print("→ Détecté: Probablement un chiffrement de César (monoalphabétique)")
            print("\nCassage en tant que César...")
            self._break_caesar(ciphertext)
        else:
            print("→ Détecté: Probablement un chiffrement de Vigenère (polyalphabétique)")
            print("\nCassage en tant que Vigenère...")
            self._break_vigenere(ciphertext)

    def frequency_analysis_workflow(self):
        """Processus d'analyse de fréquence."""
        print("\n--- ANALYSE DE FRÉQUENCE ---")

        text = input("\nEntrez le texte à analyser: ")
        if not self.validator.validate_text(text):
            print("Texte invalide. Veuillez entrer du texte.")
            return

        # Choix de la langue
        print("\nLangue de référence:")
        print("1. Français")
        print("2. Anglais")
        lang_choice = input("Votre choix (1-2): ")

        language = 'french' if lang_choice == '1' else 'english'
        analyzer = FrequencyAnalyzer(language=language)

        # Afficher l'analyse
        print("\n" + analyzer.display_frequency_chart(text, show_expected=True))

        # Informations supplémentaires
        print("\nINFORMATIONS SUPPLÉMENTAIRES:")
        print(f"Indice de coïncidence: {analyzer.index_of_coincidence(text):.4f}")
        print(f"  → IC attendu pour texte en clair: ~0.065")
        print(f"  → IC attendu pour texte aléatoire: ~0.038")

        # Séquences répétées
        sequences = analyzer.find_repeating_sequences(text, min_length=3)
        if sequences:
            print(f"\nSéquences répétées trouvées: {len(sequences)}")
            print("(Peut indiquer un chiffrement de Vigenère)")

            # Afficher quelques exemples
            count = 0
            for seq, positions in sorted(sequences.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
                print(f"  '{seq}' apparaît {len(positions)} fois aux positions {positions[:3]}...")
                count += 1

    def hashing_workflow(self):
        """Processus de hachage moderne."""
        print("\n--- HACHAGE MODERNE ---")
        print("1. Comparer les algorithmes de hachage")
        print("2. Générer un hash pour un mot de passe")
        print("3. Simuler une base de données de mots de passe")
        print("4. Démonstration rainbow table")
        print("5. Benchmark de performance")
        print("6. Démonstration salt/pepper")
        print("7. Retour au menu principal")

        choice = input("\nVotre choix (1-7): ")

        if choice == '1':
            self._hash_comparison()
        elif choice == '2':
            self._generate_password_hash()
        elif choice == '3':
            self._password_database_simulation()
        elif choice == '4':
            self._rainbow_table_demo()
        elif choice == '5':
            self._performance_benchmark()
        elif choice == '6':
            self._salt_pepper_demo()
        elif choice == '7':
            return
        else:
            print("Option invalide.")

    def _hash_comparison(self):
        """Compare tous les algorithmes de hachage."""
        text = input("\nEntrez le texte à hacher: ")
        print("\n" + self.hash_engine.compare_hashes(text))

    def _generate_password_hash(self):
        """Génère un hash sécurisé pour un mot de passe."""
        password = input("\nEntrez le mot de passe: ")

        print("\nMéthodes disponibles:")
        print("1. bcrypt (RECOMMANDÉ)")
        print("2. PBKDF2")
        print("3. SHA-256 + Salt")

        choice = input("Votre choix (1-3): ")

        if choice == '1':
            hash_result = self.hash_engine.hash_bcrypt(password)
            print(f"\nHash bcrypt: {hash_result}")
        elif choice == '2':
            salt = self.salt_gen.generate_salt()
            hash_result = self.salt_gen.pbkdf2_hash(password, salt)
            print(f"\nSalt: {salt}")
            print(f"Hash PBKDF2: {hash_result}")
        elif choice == '3':
            salt = self.salt_gen.generate_salt()
            hash_result = self.salt_gen.hash_with_salt(password, salt)
            print(f"\nSalt: {salt}")
            print(f"Hash SHA-256: {hash_result}")

    def _password_database_simulation(self):
        """Simule une base de données de mots de passe."""
        print("\n" + "="*50)
        print("SIMULATION DE BASE DE DONNÉES")
        print("="*50)

        # Créer une nouvelle instance pour cette démo
        db = PasswordDatabase()

        # Ajouter quelques utilisateurs de démo
        db.add_user("alice", "password123", method='insecure_md5')
        db.add_user("bob", "SecureP@ss456", method='sha256_salt')
        db.add_user("charlie", "MyPassword789!", method='pbkdf2')
        db.add_user("diana", "Str0ng!Pass", method='bcrypt')

        print("\n4 utilisateurs créés avec différentes méthodes")
        print("\nAnalyse de sécurité:")
        print(db.analyze_security())

        print("\nSimulation de violation:")
        print(db.demonstrate_database_breach())

    def _rainbow_table_demo(self):
        """Démontre les attaques par rainbow table."""
        print("\n" + self.rainbow_sim.demonstrate_rainbow_table_attack())

    def _performance_benchmark(self):
        """Benchmark des performances."""
        print("\nBenchmark en cours (1000 hachages par algorithme)...")
        print("Cela peut prendre 30-60 secondes...")

        results = self.hash_engine.benchmark_algorithms(iterations=1000)

        print("\n" + "="*70)
        print("RÉSULTATS DU BENCHMARK")
        print("="*70)
        print(f"{'Algorithme':<15} | {'Temps (s)':<12} | {'Hash/sec':<15}")
        print("-"*70)

        for algo, time_taken in sorted(results.items(), key=lambda x: x[1]):
            hashes_per_sec = 1000 / time_taken if time_taken > 0 else float('inf')
            print(f"{algo:<15} | {time_taken:11.4f}s | {hashes_per_sec:14.0f}")

        print("="*70)
        print("\nOBSERVATION: bcrypt est intentionnellement lent (sécurité!)")

    def _salt_pepper_demo(self):
        """Démontre l'importance des salts et peppers."""
        print("\n" + self.salt_gen.demonstrate_salt_importance())

    def john_the_ripper_workflow(self):
        """Processus John the Ripper."""
        print("\n--- JOHN THE RIPPER ---")

        # Vérifier l'installation
        if not self.jtr_wrapper.is_installed:
            print("\n⚠ ATTENTION: John the Ripper n'est pas installé!")
            print("\nPour installer John the Ripper:")
            print("  Ubuntu/Debian: sudo apt-get install john")
            print("  macOS:         brew install john")
            print("  Windows:       Télécharger depuis https://www.openwall.com/john/")
            print("\nVous pouvez quand même générer des fichiers de hashes et des wordlists.")
            print("")

        print("1. Générer un fichier de hashes pour JtR")
        print("2. Créer une wordlist personnalisée")
        print("3. Lancer John the Ripper (nécessite JtR installé)")
        print("4. Afficher les résultats d'une session")
        print("5. Benchmark de John the Ripper")
        print("6. Démonstration complète")
        print("7. Retour au menu principal")

        choice = input("\nVotre choix (1-7): ")

        if choice == '1':
            self._generate_hash_file()
        elif choice == '2':
            self._create_wordlist()
        elif choice == '3':
            self._run_john_the_ripper()
        elif choice == '4':
            self._show_jtr_results()
        elif choice == '5':
            self._jtr_benchmark()
        elif choice == '6':
            self._jtr_full_demo()
        elif choice == '7':
            return
        else:
            print("Option invalide.")

    def _generate_hash_file(self):
        """Génère un fichier de hashes pour JtR."""
        print("\n--- GÉNÉRATION DE FICHIER DE HASHES ---")
        print("1. Hashes MD5 (facile à casser)")
        print("2. Hashes SHA-256")
        print("3. Hashes bcrypt (difficile)")
        print("4. Depuis une base de données simulée")

        choice = input("\nVotre choix (1-4): ")

        if choice == '4':
            # Créer une base de données de démonstration
            demo_db = PasswordDatabase()
            demo_db.add_user("alice", "password123", method='insecure_md5')
            demo_db.add_user("bob", "qwerty", method='insecure_md5')
            demo_db.add_user("charlie", "admin", method='insecure_md5')
            demo_db.add_user("diana", "SecureP@ss456", method='bcrypt')

            files = self.hash_gen.generate_from_password_db(demo_db)

            print("\nFichiers générés:")
            for method, filepath in files.items():
                print(f"\n{method.upper()}:")
                print(self.hash_gen.display_file_info(filepath))

        else:
            # Mots de passe de test
            test_passwords = ["password", "123456", "qwerty", "admin", "letmein"]

            if choice == '1':
                filepath = self.hash_gen.create_test_hashes(test_passwords, method='md5')
                format_hint = 'raw-md5'
            elif choice == '2':
                filepath = self.hash_gen.create_test_hashes(test_passwords, method='sha256')
                format_hint = 'raw-sha256'
            elif choice == '3':
                print("\nGénération de hashes bcrypt (peut prendre quelques secondes)...")
                import bcrypt
                hashes = {}
                for i, pwd in enumerate(test_passwords):
                    hashes[f"user{i+1}"] = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()
                filepath = self.hash_gen.generate_bcrypt(hashes)
                format_hint = 'bcrypt'
            else:
                return

            print(f"\nFichier créé: {filepath}")
            print(f"Format John: {format_hint}")
            print(self.hash_gen.display_file_info(filepath))

    def _create_wordlist(self):
        """Crée une wordlist personnalisée."""
        print("\n--- CRÉATION DE WORDLIST ---")
        print("1. Wordlist de mots de passe courants (100+ entrées)")
        print("2. Wordlist numérique (ex: 0000-9999)")
        print("3. Wordlist avec patterns (variations)")

        choice = input("\nVotre choix (1-3): ")

        if choice == '1':
            filepath = self.wordlist_mgr.create_common_wordlist()
            print(f"\nWordlist créée: {filepath}")
            print(self.wordlist_mgr.display_wordlist_info(filepath))

        elif choice == '2':
            min_len = int(input("Longueur minimale (1-6): ") or "4")
            max_len = int(input("Longueur maximale (1-6): ") or "6")

            print(f"\n⚠ ATTENTION: Cela va générer {10**max_len - 10**(min_len-1)} entrées!")
            confirm = input("Continuer? (o/n): ")

            if confirm.lower() == 'o':
                filepath = self.wordlist_mgr.create_numeric_wordlist(min_len, max_len)
                print(f"\nWordlist créée: {filepath}")
                print(self.wordlist_mgr.display_wordlist_info(filepath))

        elif choice == '3':
            print("\nEntrez des mots de base (séparés par des virgules):")
            words_input = input("> ")
            base_words = [w.strip() for w in words_input.split(',')]

            add_numbers = input("Ajouter des chiffres? (o/n): ").lower() == 'o'
            add_symbols = input("Ajouter des symboles? (o/n): ").lower() == 'o'

            filepath = self.wordlist_mgr.create_pattern_wordlist(
                base_words,
                add_numbers=add_numbers,
                add_symbols=add_symbols
            )

            print(f"\nWordlist créée: {filepath}")
            print(self.wordlist_mgr.display_wordlist_info(filepath))

    def _run_john_the_ripper(self):
        """Lance John the Ripper."""
        if not self.jtr_wrapper.is_installed:
            print("\n❌ John the Ripper n'est pas installé!")
            return

        print("\n--- LANCER JOHN THE RIPPER ---")

        # Fichier de hashes
        hash_file = input("\nChemin vers le fichier de hashes: ")
        if not os.path.exists(hash_file):
            print(f"Fichier non trouvé: {hash_file}")
            return

        # Format
        print("\nFormats courants:")
        print("  raw-md5, raw-sha256, raw-sha512, bcrypt")
        format_type = input("Format (laisser vide pour auto-détection): ").strip()

        # Wordlist
        use_wordlist = input("\nUtiliser une wordlist? (o/n): ").lower() == 'o'
        wordlist = None

        if use_wordlist:
            wordlist = input("Chemin vers la wordlist: ")
            if not os.path.exists(wordlist):
                print(f"Wordlist non trouvée: {wordlist}")
                return

        # Timeout
        timeout = input("\nTimeout en secondes (laisser vide pour 60): ").strip()
        timeout = int(timeout) if timeout else 60

        print(f"\n🔓 Lancement de John the Ripper (timeout: {timeout}s)...")

        success, output = self.jtr_wrapper.crack_hash_file(
            hash_file,
            wordlist=wordlist,
            format_type=format_type or None,
            timeout=timeout
        )

        if success:
            print("\n✅ Exécution terminée!")
            print("\nSortie de John:")
            print("-" * 70)
            print(output)
            print("-" * 70)

            # Récupérer les résultats
            cracked = self.jtr_wrapper.show_cracked(hash_file, format_type or None)

            if cracked:
                print("\n" + self.result_parser.format_crack_results(cracked, 5, timeout))
                print("\n" + self.result_parser.display_password_analysis(list(cracked.values())))
            else:
                print("\n⚠ Aucun mot de passe cassé dans le temps imparti.")

        else:
            print(f"\n❌ Erreur: {output}")

    def _show_jtr_results(self):
        """Affiche les résultats d'une session JtR."""
        if not self.jtr_wrapper.is_installed:
            print("\n❌ John the Ripper n'est pas installé!")
            return

        hash_file = input("\nChemin vers le fichier de hashes: ")
        format_type = input("Format (laisser vide si inconnu): ").strip() or None

        cracked = self.jtr_wrapper.show_cracked(hash_file, format_type)

        if cracked:
            print("\n" + self.result_parser.format_crack_results(cracked, len(cracked)))
            print("\n" + self.result_parser.display_password_analysis(list(cracked.values())))
        else:
            print("\n⚠ Aucun résultat trouvé.")

    def _jtr_benchmark(self):
        """Lance un benchmark de JtR."""
        if not self.jtr_wrapper.is_installed:
            print("\n❌ John the Ripper n'est pas installé!")
            return

        print("\n🔥 Lancement du benchmark John the Ripper...")
        print("Cela peut prendre 30-60 secondes...\n")

        benchmarks = self.jtr_wrapper.benchmark()

        if benchmarks:
            print("="*80)
            print("RÉSULTATS DU BENCHMARK")
            print("="*80)
            print(f"{'Format':<30} | {'Vitesse (hashes/sec)':<20}")
            print("-"*80)

            for format_name, speed in sorted(benchmarks.items(), key=lambda x: x[1], reverse=True)[:15]:
                print(f"{format_name:<30} | {speed:>18,}")

            print("="*80)
        else:
            print("❌ Impossible de récupérer les résultats du benchmark.")

    def _jtr_full_demo(self):
        """Démonstration complète de John the Ripper."""
        print("\n" + "="*80)
        print("DÉMONSTRATION COMPLÈTE: JOHN THE RIPPER")
        print("="*80)

        # Étape 1: Créer une base de données vulnérable
        print("\nÉTAPE 1: Création d'une base de données de test")
        print("-"*80)

        demo_db = PasswordDatabase()
        demo_db.add_user("alice", "password", method='insecure_md5')
        demo_db.add_user("bob", "123456", method='insecure_md5')
        demo_db.add_user("charlie", "qwerty", method='insecure_md5')
        demo_db.add_user("diana", "admin", method='insecure_md5')
        demo_db.add_user("eve", "letmein", method='insecure_md5')

        print("✅ 5 utilisateurs créés avec MD5 (NON SÉCURISÉ)")

        # Étape 2: Générer le fichier de hashes
        print("\nÉTAPE 2: Génération du fichier de hashes")
        print("-"*80)

        files = self.hash_gen.generate_from_password_db(demo_db, 'demo_hashes')
        hash_file = files.get('md5')

        print(f"✅ Fichier créé: {hash_file}")
        print(self.hash_gen.display_file_info(hash_file))

        # Étape 3: Créer une wordlist
        print("\nÉTAPE 3: Création d'une wordlist")
        print("-"*80)

        wordlist_file = self.wordlist_mgr.create_common_wordlist('demo_wordlist.txt')
        print(f"✅ Wordlist créée: {wordlist_file}")

        stats = self.wordlist_mgr.get_wordlist_stats(wordlist_file)
        print(f"   Contient {stats['total_lines']} mots de passe courants")

        # Étape 4: Lancer JtR (si installé)
        if self.jtr_wrapper.is_installed:
            print("\nÉTAPE 4: Lancement de John the Ripper")
            print("-"*80)

            import time
            start_time = time.time()

            success, output = self.jtr_wrapper.crack_hash_file(
                hash_file,
                wordlist=wordlist_file,
                format_type='raw-md5',
                timeout=30
            )

            time_taken = time.time() - start_time

            if success:
                cracked = self.jtr_wrapper.show_cracked(hash_file, 'raw-md5')
                print(f"\n✅ Cassage terminé en {time_taken:.2f} secondes!")
                print(self.result_parser.format_crack_results(cracked, 5, time_taken))

                if cracked:
                    print(self.result_parser.display_password_analysis(list(cracked.values())))

                    print("\n" + "="*80)
                    print("CONCLUSION:")
                    print("="*80)
                    print("→ MD5 sans salt est EXTRÊMEMENT vulnérable")
                    print(f"→ {len(cracked)}/5 mots de passe cassés en < {time_taken:.1f}s")
                    print("→ TOUJOURS utiliser bcrypt/PBKDF2 avec salt!")
                    print("="*80)
            else:
                print(f"⚠ Erreur lors du cassage: {output}")

        else:
            print("\nÉTAPE 4: Simulation (JtR non installé)")
            print("-"*80)
            print("Si John the Ripper était installé, il casserait probablement")
            print("tous ces mots de passe en quelques secondes car:")
            print("  → MD5 est très rapide (millions de hash/seconde)")
            print("  → Pas de salt (rainbow tables efficaces)")
            print("  → Mots de passe très courants")
            print("\nInstallez JtR pour voir la démonstration réelle!")


if __name__ == "__main__":
    cli = CLI()
    cli.run()