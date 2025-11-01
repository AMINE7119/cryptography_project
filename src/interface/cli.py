import sys
import os

# Ajouter le répertoire parent au path pour les imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto_engine import CryptoEngine
from utils.validators import InputValidator
from cryptanalysis.caesar_breaker import CaesarBreaker
from cryptanalysis.vigenere_breaker import VigenereBreaker
from cryptanalysis.frequency_analysis import FrequencyAnalyzer

class CLI:
    """Interface en ligne de commande pour l'application de cryptographie."""
    
    def __init__(self):
        """Initialise l'interface CLI avec le moteur de cryptographie."""
        self.engine = CryptoEngine()
        self.validator = InputValidator()
        self.caesar_breaker = CaesarBreaker()
        self.vigenere_breaker = VigenereBreaker()
        self.frequency_analyzer = FrequencyAnalyzer()
        
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
        print("5. Quitter")
        
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
            choice = input("\nVotre choix (1-5): ")

            if choice == '1':
                self.encrypt_workflow()
            elif choice == '2':
                self.decrypt_workflow()
            elif choice == '3':
                self.cryptanalysis_workflow()
            elif choice == '4':
                self.frequency_analysis_workflow()
            elif choice == '5':
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


if __name__ == "__main__":
    cli = CLI()
    cli.run()