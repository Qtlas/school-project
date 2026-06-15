#include <stdio.h>
#include <stdlib.h>

#define MAX 10

struct Pile {
  int sommet;
  int tab[MAX];
};

typedef struct Pile Pile;

Pile* creer_pile() {
  Pile *pile = malloc(sizeof(Pile));
  pile->sommet = -1;
  return pile;
}

int pile_vide(Pile *pile){
  return pile->sommet == -1;
}

int pile_pleine(Pile *pile){
  return pile->sommet == MAX - 1;
}

int empiler(Pile *pile, int x) {
  if (pile_pleine(pile)) {
    return 0;
  } else {
    pile->sommet += 1;
    pile->tab[pile->sommet] = x;
    return 1;
  }
}

int depiler(Pile *pile){
  if (pile_vide(pile)) {
    return 0;
  } else {
    int x = pile->tab[pile->sommet];
    pile->sommet--;
    return x;
  }
}

void afficher_pile(Pile *pile) {
  for (int i = pile->sommet; i >= 0; i--) {
    printf(" %d \n", pile->tab[i]);
  }
}

int main() {
  Pile *pile = creer_pile();

  printf("La pile est : %s\n", pile_vide(pile) ? "vide" : "n'est pas vide");

  for (int i = 1; i <= 10; i++) empiler(pile, i);

  printf("La pile est : %s\n\n", pile_pleine(pile) ? "pleine" : "n'est pas pleine");

  afficher_pile(pile);

  depiler(pile);
  printf("\nApres un depilage :\n");
  afficher_pile(pile);

  free(pile);
  return 0;
}
