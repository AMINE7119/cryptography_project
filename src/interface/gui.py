import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# Ajouter le répertoire parent au path pour les imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto_engine import CryptoEngine
from utils.validators import InputValidator
from utils.key_generator import KeyGenerator

class CryptoGUI:
    """Interface graphique pour l'application de cryptographie."""
    
    def __init__(self, root):
        """
        Initialise l'interface graphique.
        
        Args:
            root (tk.Tk): La fenêtre principale
        """
        self.root = root
        self.root.title("Outils de Cryptographie")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        self.engine = CryptoEngine()
        self.validator = InputValidator()
        self.key_generator = KeyGenerator()
        
        self.create_widgets()
        self.setup_styles()
        
    def setup_styles(self):
        """Configure les styles pour l'interface."""
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        style.configure("TButton", font=("Arial", 10))
        style.configure("Header.TLabel", font=("Arial", 16, "bold"))
        
    def create_widgets(self):
        """Crée tous les widgets de l'interface."""
        # Frame principal
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Titre
        header_label = ttk.Label(main_frame, text="Outils de Cryptographie", style="Header.TLabel")
        header_label.pack(pady=10)
        
        # Frame pour la sélection de l'algorithme
        algo_frame = ttk.LabelFrame(main_frame, text="Algorithme", padding=10)
        algo_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Combobox pour sélectionner l'algorithme
        self.algo_var = tk.StringVar()
        algorithms = self.engine.get_available_algorithms()
        self.algo_combo = ttk.Combobox(algo_frame, textvariable=self.algo_var, values=algorithms, state="readonly")
        self.algo_combo.pack(fill=tk.X, padx=5, pady=5)
        self.algo_combo.current(0)  # Sélectionner le premier algorithme par défaut
        self.algo_combo.bind("<<ComboboxSelected>>", self.on_algorithm_changed)
        
        # Frame pour la clé
        key_frame = ttk.LabelFrame(main_frame, text="Clé", padding=10)
        key_frame.pack(fill=tk.X, padx=5, pady=5)
        
        key_input_frame = ttk.Frame(key_frame)
        key_input_frame.pack(fill=tk.X, expand=True)
        
        self.key_label = ttk.Label(key_input_frame, text="Clé:")
        self.key_label.pack(side=tk.LEFT, padx=5)
        
        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(key_input_frame, textvariable=self.key_var)
        self.key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.generate_key_button = ttk.Button(key_input_frame, text="Générer une clé", command=self.generate_key)
        self.generate_key_button.pack(side=tk.RIGHT, padx=5)
        
        # Frame pour le texte
        text_frame = ttk.LabelFrame(main_frame, text="Texte", padding=10)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Zone de texte d'entrée
        input_frame = ttk.Frame(text_frame)
        input_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        
        ttk.Label(input_frame, text="Texte d'entrée:").pack(anchor=tk.W)
        
        self.input_text = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=10)
        self.input_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Boutons d'action
        action_frame = ttk.Frame(text_frame)
        action_frame.pack(fill=tk.Y, padx=5)
        
        self.encrypt_button = ttk.Button(action_frame, text="Chiffrer >>", command=self.encrypt)
        self.encrypt_button.pack(pady=10)
        
        self.decrypt_button = ttk.Button(action_frame, text="<< Déchiffrer", command=self.decrypt)
        self.decrypt_button.pack(pady=10)
        
        # Zone de texte de sortie
        output_frame = ttk.Frame(text_frame)
        output_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT)
        
        ttk.Label(output_frame, text="Texte de sortie:").pack(anchor=tk.W)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=10)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Boutons de copie
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.copy_output_button = ttk.Button(button_frame, text="Copier le résultat", command=self.copy_output)
        self.copy_output_button.pack(side=tk.RIGHT, padx=5)
        
        self.clear_button = ttk.Button(button_frame, text="Effacer tout", command=self.clear_all)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Initialisation des widgets de clé
        self.on_algorithm_changed(None)
        
    def on_algorithm_changed(self, event):
        """
        Met à jour l'interface en fonction de l'algorithme sélectionné.
        
        Args:
            event: L'événement de sélection
        """
        algorithm = self.algo_var.get()
        
        if algorithm == "César":
            self.key_label.config(text="Clé (0-25):")
            self.key_var.set("3")  # Valeur par défaut
        elif algorithm == "Vigenère":
            self.key_label.config(text="Mot-clé:")
            self.key_var.set("SECRET")  # Valeur par défaut
        elif algorithm == "Playfair":
            self.key_label.config(text="Mot-clé:")
            self.key_var.set("CRYPTOGRAPHIE")  # Valeur par défaut
    
    def generate_key(self):
        """Génère une clé aléatoire pour l'algorithme sélectionné."""
        algorithm = self.algo_var.get()
        
        try:
            if algorithm == "César":
                key = self.key_generator.generate_caesar_key()
                self.key_var.set(str(key))
            elif algorithm == "Vigenère":
                key = self.key_generator.generate_vigenere_key()
                self.key_var.set(key)
            elif algorithm == "Playfair":
                key = self.key_generator.generate_playfair_key()
                self.key_var.set(key)
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la génération de la clé: {e}")
    
    def encrypt(self):
        """Chiffre le texte d'entrée et affiche le résultat."""
        algorithm = self.algo_var.get()
        key = self.key_var.get()
        text = self.input_text.get("1.0", tk.END).strip()
        
        if not text:
            messagebox.showwarning("Avertissement", "Veuillez entrer du texte à chiffrer.")
            return
        
        # Validation de la clé
        valid_key = False
        if algorithm == "César":
            valid_key = self.validator.validate_caesar_key(key)
            if valid_key:
                key = int(key)
        elif algorithm == "Vigenère":
            valid_key = self.validator.validate_vigenere_key(key)
        elif algorithm == "Playfair":
            valid_key = self.validator.validate_playfair_key(key)
        
        if not valid_key:
            messagebox.showwarning("Avertissement", "Clé invalide pour cet algorithme.")
            return
        
        try:
            encrypted = self.engine.encrypt(text, algorithm, key)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", encrypted)
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du chiffrement: {e}")
    
    def decrypt(self):
        """Déchiffre le texte d'entrée et affiche le résultat."""
        algorithm = self.algo_var.get()
        key = self.key_var.get()
        text = self.input_text.get("1.0", tk.END).strip()
        
        if not text:
            messagebox.showwarning("Avertissement", "Veuillez entrer du texte à déchiffrer.")
            return
        
        # Validation de la clé
        valid_key = False
        if algorithm == "César":
            valid_key = self.validator.validate_caesar_key(key)
            if valid_key:
                key = int(key)
        elif algorithm == "Vigenère":
            valid_key = self.validator.validate_vigenere_key(key)
        elif algorithm == "Playfair":
            valid_key = self.validator.validate_playfair_key(key)
        
        if not valid_key:
            messagebox.showwarning("Avertissement", "Clé invalide pour cet algorithme.")
            return
        
        try:
            decrypted = self.engine.decrypt(text, algorithm, key)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", decrypted)
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du déchiffrement: {e}")
    
    def copy_output(self):
        """Copie le texte de sortie dans le presse-papiers."""
        output = self.output_text.get("1.0", tk.END).strip()
        if output:
            self.root.clipboard_clear()
            self.root.clipboard_append(output)
            messagebox.showinfo("Information", "Texte copié dans le presse-papiers.")
    
    def clear_all(self):
        """Efface tous les champs de texte."""
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()