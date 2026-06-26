# TP3 Lexiques sous forme de listes chaînées triées

Travail pratique sur les listes chaînées triées, appliquées à la gestion
de **lexiques** : chaque mot est stocké une seule fois avec son nombre
d'occurrences, la liste étant maintenue triée par ordre alphabétique.

## Contenu

- **`tp3.h`**  Définition de la structure `t_mot` (mot, nombre
  d'occurrences, pointeur vers le suivant) et des prototypes.
- **`tp3.c`**  Implémentation :
  - `toLowerCase` : conversion en minuscules.
  - `creerMot` / `ajouterMot` : création et insertion triée d'un mot
    (incrémente le compteur si le mot existe déjà).
  - `retirerMot` : retrait d'une occurrence d'un mot (suppression du nœud
    si le compteur atteint zéro).
  - `afficherMots` : affichage du lexique groupé par lettre initiale.
  - `fusionner` : fusion de deux lexiques triés en un seul, en sommant les
    occurrences des mots communs.
  - `importerFichier` : chargement d'un lexique à partir d'un fichier
    texte (un mot par ligne).
  - `detruireListe` : libération de la mémoire.
- **`main.c`**  Menu interactif permettant de manipuler deux lexiques
  (`l1` et `l2`) : affichage, ajout, retrait, fusion, import depuis
  fichier.
- **`test.txt`** Fichier de test (texte d'exemple, un mot par ligne) pour
  l'option d'import.

## Compilation et exécution

```sh
make
./tp3
make clean
```

Au lancement, le menu propose :

```
[1] Afficher un lexique
[2] Ajouter un mot dans un lexique
[3] Retirer un mot d'un lexique
[4] Fusionner deux lexiques
[5] Charger un fichier dans un lexique
[6] Quitter
```

L'option `[5]` charge le contenu de `test.txt` (le fichier doit se trouver
dans le répertoire courant lors de l'exécution).
