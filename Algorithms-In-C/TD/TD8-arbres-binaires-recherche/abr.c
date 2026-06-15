#include <stdio.h>
#include <stdlib.h>

typedef struct Abr {
  int cle;
  struct Abr *filsG;
  struct Abr *filsD;
} Abr;

Abr *creer_noeud(int v){
  Abr *nouveau_arbre = malloc(sizeof(Abr));
  nouveau_arbre->cle = v;
  nouveau_arbre->filsG = NULL;
  nouveau_arbre->filsD = NULL;
  return nouveau_arbre;
}

Abr *recherche(Abr *abr, int v){
  /*
  Recherche valeur x dans abr :
    Meileur cas : si la racine == x -> complexite en Ω(1)
    Pire cas : si la x n'est pas dans abr -> complexite en O(h) ou h est la hauteur de l'abr
  */
  if (abr == NULL || abr->cle == v) return abr;
  else if (abr->cle > v) return recherche(abr->filsG, v);
  else return recherche(abr->filsD, v);
}

Abr *min(Abr *abr) {
  /*
  Rechercher valeur minimun dans abr qui est par definition de l'abr tout a a gauche:
  Meilleur cas : racine na pas de fils gauche -> complexeite en omega(1)
  Pire cas : complexite en O(h) ou h = hauteur abr
  */
  if (abr->filsG == NULL) return abr;
  return min(abr->filsG);
}

Abr *max(Abr *abr) {
  /*
  Rechercher valeur maximum dans abr qui est par definition de l'abr tout a a droite:
  Meilleur cas : racine na pas de fils droite -> complexeite en omega(1)
  Pire cas : complexite en O(h) ou h = hauteur abr
  */
  if (abr->filsD == NULL) return abr;
  return max(abr->filsD);
}

Abr *inserer(Abr  *abr, int v){
  if (abr == NULL) return creer_noeud(v);
  else if (abr->cle > v) abr->filsG = inserer(abr->filsG, v);
  else abr->filsD = inserer(abr->filsD, v);
  return abr;
}



void prefixe(Abr *abr){
  if(abr != NULL){
    printf("%d ", abr->cle);
    prefixe(abr->filsG);
    prefixe(abr->filsD);
  }
}

int main() {
  Abr *abr = NULL;
  abr = inserer(abr, 10);
  abr = inserer(abr, 5);
  abr = inserer(abr, 15);
  abr = inserer(abr, 3);
  abr = inserer(abr, 7);
  abr = inserer(abr, 12);
  abr = inserer(abr, 18);
  prefixe(abr);
  printf("\n");
  printf("Max : %d\n", max(abr)->cle);
  printf("Min : %d\n", min(abr)->cle);

  return 0;
}
