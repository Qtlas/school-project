# TD7 Piles, files et arbres binaires

Travaux dirigés sur les structures de données linéaires (pile, file) et sur
les parcours itératifs d'arbres binaires à l'aide d'une pile.

## Contenu

- **`pile.c`**  Implémentation d'une pile (LIFO) sur tableau statique :
  `empiler`, `depiler`, `pile_vide`, `pile_pleine`, `afficher_pile`.
- **`file.c`**  Implémentation d'une file (FIFO) circulaire sur tableau
  statique : `enfiler`, `defiler`, `file_vide`, `file_pleine`,
  `afficher_file`.
- **`arbre.c`** Deux structures d'arbres et leurs parcours :
  - `Cellule` (arbre fils-gauche / frère-droit) avec un affichage par
    profondeur (`affiche_par_profondeur`).
  - `ArbreB` (arbre binaire classique fils gauche / fils droit) avec les
    parcours **préfixe**, **infixe** et **postfixe** réalisés de manière
    **itérative** à l'aide d'une pile.
  - Évaluation d'une expression en **notation polonaise inversée** (NPI /
    RPN) via une pile de flottants (`caclule_polonaise`).

## Sujet

Le sujet du TD est disponible dans [`sujet/TD7.pdf`](sujet/TD7.pdf).

## Compilation et exécution

```sh
make          # compile pile, file et arbre
./pile
./file
./arbre
make clean    # supprime les exécutables
```