# TD8 — Arbres binaires de recherche (ABR)

Travaux dirigés sur les arbres binaires de recherche : insertion,
recherche, recherche du minimum/maximum et parcours préfixe, avec une
étude de la complexité (meilleur cas / pire cas en fonction de la hauteur
de l'arbre).

## Contenu

- **`abr.c`** — Implémentation d'un ABR d'entiers :
  - `creer_noeud` / `inserer` : création et insertion récursive.
  - `recherche` : recherche récursive d'une clé (Ω(1) au mieux,
    O(h) au pire, où `h` est la hauteur de l'arbre).
  - `min` / `max` : recherche récursive du minimum / maximum.
  - `prefixe` : parcours préfixe récursif (affichage).

## Sujet et corrigé

- Sujet : [`sujet/TD8.pdf`](sujet/TD8.pdf)
- Corrigé : [`sujet/TD8_corrige.pdf`](sujet/TD8_corrige.pdf)

## Compilation et exécution

```sh
make
./abr
make clean
```

## Notes

La fonction `recherche` du fichier original ne renvoyait pas le résultat
des appels récursifs (`return` manquant). Ce point a été corrigé pour que
la fonction renvoie effectivement le nœud trouvé (ou `NULL`).
