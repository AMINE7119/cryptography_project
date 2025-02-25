"""
Module de configuration pour l'application de cryptographie.
"""

import os
from dotenv import load_dotenv

# Chargement des variables d'environnement du fichier .env s'il existe
load_dotenv()

# Configuration des algorithmes
ALGORITHMS = {
    "César": {
        "description": "Chiffrement par substitution avec décalage fixe",
        "key_type": "int",
        "key_range": (0, 25)
    },
    "Vigenère": {
        "description": "Chiffrement polyalphabétique utilisant une clé textuelle",
        "key_type": "str",
        "min_key_length": 1
    },
    "Playfair": {
        "description": "Chiffrement par substitution utilisant une matrice 5x5",
        "key_type": "str",
        "min_key_length": 1
    }
}

# Configuration de l'application
APP_NAME = "Outils de Cryptographie"
APP_VERSION = "1.0.0"
AUTHOR = "AMINE7119"

# Paramètres de formatage
DEFAULT_BLOCK_SIZE = 5  # Taille des blocs pour le formatage du texte chiffré

# Chemins
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))