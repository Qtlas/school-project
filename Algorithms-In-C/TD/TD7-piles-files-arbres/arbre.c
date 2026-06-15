#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAILLE_PILE 255

typedef struct Cellule {
  int cle;
  struct Cellule *filsG;
  struct Cellule *frereD;
} Cellule;

typedef struct ArbreB {
  int cle;
  struct ArbreB *filsG;
  struct ArbreB *filsD;
} ArbreB;

typedef struct Pile{
  int sommet;
  ArbreB* tab[TAILLE_PILE];
} Pile;

typedef struct Pile_nb {
  float tab[TAILLE_PILE];
  int sommet;
} Pile_nb;

Cellule *creer_cellule(){
  Cellule *cellule = malloc(sizeof(Cellule));
  cellule->filsG = NULL;
  cellule->frereD = NULL;
  return cellule;
}

void affiche_par_profondeur(Cellule *cellule){
  Cellule *temp = cellule, *temp2=NULL;
  int found = 0;
  do {
    printf("%d ", temp->cle);
    if (!found && temp->filsG != NULL){
      temp2 = temp;
      found = 1;
    }
    temp = temp->frereD;
  } while(temp != NULL);

  printf("\n");
  if (temp2 != NULL) affiche_par_profondeur(temp2->filsG);
}

Pile *creer_pile(){
  Pile *pile = malloc(sizeof(Pile));
  pile->sommet = 0;
  return pile;
}

int pile_vide(Pile *pile) {
  return pile->sommet == 0;
}

int pile_pleine(Pile *pile){
  return pile->sommet == TAILLE_PILE;
}

void empiler(Pile *pile, ArbreB *noeud){
  if (pile_pleine(pile)) printf("Pile pleine !\n");
  else {
    pile->tab[pile->sommet] = noeud;
    pile->sommet += 1;
  }
}

ArbreB *depiler(Pile *pile){
  if (pile_vide(pile)) return NULL;
  pile->sommet--;
  return pile->tab[pile->sommet];
}

ArbreB *creer_ab() {
  ArbreB *ab = malloc(sizeof(ArbreB));
  ab->filsG = NULL;
  ab->filsD = NULL;
  return ab;
}

void parcours_prefixe_ite(ArbreB *ab){
  Pile *pile = creer_pile();
  if (ab != NULL) empiler(pile, ab);
  ArbreB *temp = depiler(pile);
  while(temp != NULL){
    printf("%d ", temp->cle);
    if(temp->filsD) empiler(pile, temp->filsD);
    if(temp->filsG) empiler(pile, temp->filsG);
    temp = depiler(pile);
  }
  printf("\n");
}

void parcours_infixe_ite(ArbreB* racine) {
    Pile *pile = creer_pile();
    ArbreB* courant = racine;
    while (courant != NULL || !pile_vide(pile)) {
        while (courant != NULL) {
            empiler(pile, courant);
            courant = courant->filsG;
        }
        courant = depiler(pile);
        printf("%d ", courant->cle);
        courant = courant->filsD;
    }
    printf("\n");
}

void parcours_postfixe_ite(ArbreB *racine) {
    if (racine == NULL) return;

    Pile *pile1 = creer_pile();
    Pile *pile2 = creer_pile();

    empiler(pile1, racine);

    while (!pile_vide(pile1)) {
        ArbreB *courant = depiler(pile1);
        empiler(pile2, courant);

        if (courant->filsG != NULL)
            empiler(pile1, courant->filsG);
        if (courant->filsD != NULL)
            empiler(pile1, courant->filsD);
    }

    while (!pile_vide(pile2)) {
        ArbreB *noeud = depiler(pile2);
        printf("%d ", noeud->cle);
    }
    printf("\n");
}

Pile_nb *creer_pile_nb(){
  Pile_nb *pile = malloc(sizeof(Pile_nb));
  pile->sommet = 0;
  return pile;
}

int pile_vide_nb(Pile_nb *pile){
  return pile->sommet == 0;
}

int pile_pleine_nb(Pile_nb *pile){
  return pile->sommet == TAILLE_PILE;
}

void empiler_nb(Pile_nb *pile, float x){
  if (!pile_pleine_nb(pile)) pile->tab[pile->sommet++] = x;
}

float depiler_nb(Pile_nb *pile) {
  if(!pile_vide_nb(pile)) return pile->tab[--pile->sommet];
  return 0.0;
}

float caclule_polonaise(char chaine[]){
  Pile_nb *pile = creer_pile_nb();
  float result=0.0;
  for (size_t i=0; i<strlen(chaine); i++){
    if (chaine[i] >= '0' && chaine[i] <= '9') empiler_nb(pile, strtof(&chaine[i], NULL));
    else if (chaine[i] != ' '){
      float x = depiler_nb(pile);
      float y = depiler_nb(pile);
      switch(chaine[i]){
        case '+':
          result = x+y;
          break;
        case '-':
          result = x-y;
          break;
        case '*':
          result = x*y;
          break;
        case '/':
          result = x/y;
          break;
      }
      empiler_nb(pile, result);
    }
  }
  return result;
}

int main(){
  Cellule *a = creer_cellule(); a->cle = 1;
  Cellule *b = creer_cellule(); b->cle = 2;
  Cellule *c = creer_cellule(); c->cle = 3;
  Cellule *d = creer_cellule(); d->cle = 4;
  Cellule *e = creer_cellule(); e->cle = 5;
  Cellule *f = creer_cellule(); f->cle = 6;
  Cellule *g = creer_cellule(); g->cle = 7;

  a->filsG = b;
  b->frereD = c;
  c->frereD = d;

  c->filsG = e;
  e->filsG = f;
  f->frereD = g;

  affiche_par_profondeur(a);
  
  ArbreB *a2 = malloc(sizeof(ArbreB)); a2->cle = 1;
  ArbreB *b2 = malloc(sizeof(ArbreB)); b2->cle = 2;
  ArbreB *c2 = malloc(sizeof(ArbreB)); c2->cle = 3;
  ArbreB *d2 = malloc(sizeof(ArbreB)); d2->cle = 4;
  ArbreB *e2 = malloc(sizeof(ArbreB)); e2->cle = 5;
  ArbreB *f2 = malloc(sizeof(ArbreB)); f2->cle = 6;
  ArbreB *g2 = malloc(sizeof(ArbreB)); g2->cle = 7;

  a2->filsG = b2;
  a2->filsD = c2;

  b2->filsG = d2;
  b2->filsD = e2;

  c2->filsG = f2;
  c2->filsD = g2;

  d2->filsG = d2->filsD = NULL;
  e2->filsG = e2->filsD = NULL;
  f2->filsG = f2->filsD = NULL;
  g2->filsG = g2->filsD = NULL;

  parcours_prefixe_ite(a2);
  parcours_infixe_ite(a2);
  parcours_postfixe_ite(a2);

  float result = caclule_polonaise("5 9 8 + 4 6 * * 7 + *");
  printf("%5.f\n", result);
  return 0;

}
