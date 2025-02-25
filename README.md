# Outils de Cryptographie Classique 🔒

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.6+-green.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)

## 📜 Présentation
Ce projet est une suite d'outils de cryptographie implémentant plusieurs algorithmes de chiffrement classiques. Développé comme une introduction pratique à la cryptographie, il permet de comprendre concrètement comment fonctionnent les méthodes de chiffrement historiques qui constituent la base de la cryptographie moderne.

## 🎯 Objectifs du Projet
- **Éducatif** : Découvrir les fondements de la cryptographie de manière interactive
- **Pratique** : Offrir une implémentation propre et bien structurée des algorithmes classiques
- **Modulaire** : Architecture extensible permettant d'ajouter facilement de nouveaux algorithmes
- **Convivial** : Interface en ligne de commande et interface graphique pour différents usages

## 🔐 Algorithmes Implémentés

### Chiffrement de César
Un des plus anciens algorithmes connus, utilisé par Jules César pour ses communications militaires. Chaque lettre du texte est décalée d'un nombre fixe de positions dans l'alphabet.

### Chiffrement de Vigenère
Évolution du chiffrement de César, le Vigenère utilise un mot-clé pour déterminer des décalages variables, ce qui le rend beaucoup plus difficile à casser par simple analyse de fréquence.

### Chiffrement de Playfair
Première méthode pratique de chiffrement par digrammes (paires de lettres). Utilisé notamment pendant la Première Guerre mondiale, il offre une sécurité significativement améliorée par rapport aux chiffrements monoalphabétiques.

## 🚀 Installation

```bash
# Cloner le dépôt
git clone https://github.com/AMINE7119/cryptography_project.git
cd cryptography_project

# Installer les dépendances
pip install -r requirements.txt
```

## 💻 Utilisation

### Interface en Ligne de Commande
```bash
python src/interface/cli.py
```

### Interface Graphique
```bash
python src/interface/gui.py
```

## 📝 Exemple d'utilisation

```python
# Chiffrement de César
from src.algorithms.caesar import CaesarCipher

cipher = CaesarCipher()
encrypted = cipher.encrypt("HELLO", 3)
print(encrypted)  # Affiche: KHOOR

# Déchiffrement
decrypted = cipher.decrypt("KHOOR", 3)
print(decrypted)  # Affiche: HELLO
```

## 🧩 Architecture du Projet

Le projet suit une architecture modulaire bien organisée:

```
crypto-tools/
│
├── src/
│   ├── algorithms/ # Implémentations des différents algorithmes
│   ├── utils/      # Fonctions utilitaires
│   ├── interface/  # Interfaces utilisateur (CLI et GUI)
│   └── core/       # Logique centrale
│
├── tests/         # Tests unitaires
└── docs/          # Documentation détaillée
```

## 🔍 Caractéristiques

- **Architecture orientée objet** : Utilisation d'une classe abstraite de base pour tous les algorithmes
- **Tests unitaires complets** : Vérification automatisée du bon fonctionnement
- **Interfaces multiples** : Ligne de commande et interface graphique
- **Documentation exhaustive** : Guide utilisateur et description détaillée des algorithmes
- **Code commenté** : Facilement compréhensible pour les débutants

## 🧠 Intérêt Éducatif et Technique

Ce projet permet d'approfondir plusieurs concepts importants :
- Fondamentaux de la cryptographie
- Principes de conception orientée objet en Python
- Architecture de projet modulaire
- Tests unitaires et validation
- Interfaces utilisateur (CLI et GUI)

## 🤝 Contribution
Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une issue ou soumettre une pull request.

## 📜 Licence
Ce projet est sous licence MIT - voir le fichier LICENSE pour plus de détails.

---

💡 **Note** : Ce projet est développé à des fins éducatives. Les algorithmes implémentés sont historiques et ne doivent pas être utilisés pour sécuriser des données sensibles dans un contexte moderne.