import sys
import os

# Ajouter le répertoire parent au path pour les imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto_engine import CryptoEngine
from utils.validators import InputValidator

class CLI:
    """Interface en ligne de commande pour l'application de cryptographie."""
    
    def __init__(self):
        """Initialise l'interface CLI avec le moteur de cryptographie."""
        self.engine = CryptoEngine()
        self.validator = InputValidator()
        
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
        print("3. Quitter")
        
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
            choice = input("\nVotre choix (1-3): ")
            
            if choice == '1':
                self.encrypt_workflow()
            elif choice == '2':
                self.decrypt_workflow()
            elif choice == '3':
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


if __name__ == "__main__":
    cli = CLI()
    cli.run()