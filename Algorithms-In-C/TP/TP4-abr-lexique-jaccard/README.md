# TP4 — Lexiques sous forme d'arbres binaires de recherche

Suite du TP3 : le lexique n'est plus représenté par une liste chaînée
triée mais par un **arbre binaire de recherche (ABR)**, ce qui permet des
opérations de recherche/insertion/suppression en O(h) au lieu de O(n).

## Contenu

- **`abr.h`** — Définition du type `T_Arbre` (nœud d'ABR contenant un mot,
  son nombre d'occurrences et ses deux fils), de la structure `t_mot`
  (liste chaînée utilisée comme représentation intermédiaire) et de la
  pile d'arbres `t_pile_arbre` utilisée pour les parcours itératifs.
- **`abr.c`** — Implémentation :
  - `creerNoeud` / `ajouterMot` : insertion récursive dans l'ABR (en
    minuscules), incrémentation du compteur si le mot existe déjà.
  - `retirerMot` : suppression récursive d'un mot (gestion des trois cas :
    nœud feuille, un seul fils, deux fils via le successeur minimum du
    sous-arbre droit).
  - `trouverMin` : recherche itérative du minimum d'un sous-arbre.
  - `afficherArbre` : affichage infixe (ordre alphabétique), groupé par
    lettre initiale.
  - `estEquilibre` / `estEquilibreRec` : vérifie si l'arbre est équilibré
    (différence de hauteur entre sous-arbres ≤ 1 à chaque nœud).
  - `transformerArbre` / `transformerArbreRec` : transforme l'ABR en liste
    chaînée triée (`t_mot`) par parcours infixe.
  - `creer_pile` / `empiler` / `depiler` / `descenteGauche` / `parcourir` :
    pile d'arbres et parcours infixe **itératif**.
  - `jaccard` : calcule l'**indice de Jaccard** entre deux lexiques (deux
    ABR `a` et `b`), c'est-à-dire le rapport entre le nombre de mots
    communs (pondéré par les occurrences) et le nombre total de mots
    distincts des deux lexiques, en parcourant les deux arbres en
    parallèle grâce à `descenteGauche`/`parcourir`.
  - `detruireArbre` / `detruireListe` : libération de la mémoire.
- **`main.c`** — Menu interactif permettant de manipuler deux arbres
  (`a1` et `a2`) : affichage, ajout, retrait, test d'équilibre,
  transformation en liste chaînée, calcul de l'indice de Jaccard.
- **`rapport.pdf`** — Compte-rendu du TP.

## Compilation et exécution

```sh
make
./tp4
make clean
```

Menu proposé :

```
[1] Afficher un arbre
[2] Ajouter un mot dans un arbre
[3] Retirer un mot d'un arbre
[4] Vérifier si un arbre est équilibré
[5] Transformer un arbre en liste chainee
[6] Calculer l'indice de Jaccard entre a1 et a2
[7] Quitter
```

## Notes

Quelques corrections mineures ont été apportées par rapport au fichier
d'origine pour que le programme compile sans avertissement et ne plante
pas sur des arbres vides :

- ajout de `#include <stdbool.h>` dans `abr.h` (type `bool` utilisé sans
  son en-tête) ;
- ajout d'une déclaration de bloc pour le `case '6'` du menu (déclaration
  de variable directement après une étiquette `case`) ;
- gestion du cas d'un arbre vide (`NULL`) dans `transformerArbreRec` et
  `descenteGauche`, utilisées notamment par le calcul de l'indice de
  Jaccard.
