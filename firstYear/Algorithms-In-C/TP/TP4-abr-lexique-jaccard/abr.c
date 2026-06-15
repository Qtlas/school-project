#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include "abr.h"

void toLowerCase(char *str) {
    for (int i = 0; str[i]; i++){
      if(str[i] >= 65 && str[i] <= 90){
        str[i] = str[i] + 32;
      }
    }
}

T_Arbre creerNoeud(char *mot) {
    T_Arbre nouveau = malloc(sizeof(T_Noeud));

    nouveau->mot = strdup(mot);
    nouveau->nombre_occurences = 1;
    nouveau->fils_gauche = NULL;
    nouveau->fils_droit = NULL;

    return nouveau;
}

T_Arbre ajouterMot(T_Arbre a, char *mot) {
    char mot_min[256];
    strncpy(mot_min, mot, 255);
    mot_min[255] = '\0';
    toLowerCase(mot_min);

    if (a == NULL) {
        return creerNoeud(mot_min);
    }

    int cmp = strcmp(mot_min, a->mot);
    if (cmp == 0) {
        a->nombre_occurences++;
    } else if (cmp < 0) {
        a->fils_gauche = ajouterMot(a->fils_gauche, mot_min);
    } else {
        a->fils_droit = ajouterMot(a->fils_droit, mot_min);
    }
    return a;
}

T_Arbre trouverMin(T_Arbre a) {
    while (a && a->fils_gauche)
        a = a->fils_gauche;
    return a;
}

T_Arbre retirerMot(T_Arbre a, char *mot) {
    if (a == NULL) {
      printf("Le mot nest pas dedans.\n");
      return NULL;
    }

    int cmp = strcmp(mot, a->mot);
    if (cmp < 0) {
        a->fils_gauche = retirerMot(a->fils_gauche, mot);
    } else if (cmp > 0) {
        a->fils_droit = retirerMot(a->fils_droit, mot);
    } else {
        if (a->nombre_occurences > 1) {
            a->nombre_occurences--;
        } else {
            if (a->fils_gauche == NULL) {
                T_Arbre tmp = a->fils_droit;
                free(a->mot);
                free(a);
                return tmp;
            } else if (a->fils_droit == NULL) {
                T_Arbre tmp = a->fils_gauche;
                free(a->mot);
                free(a);
                return tmp;
            } else {
                T_Arbre succ = trouverMin(a->fils_droit);
                free(a->mot);
                a->mot = strdup(succ->mot);
                a->nombre_occurences = succ->nombre_occurences;
                a->fils_droit = retirerMot(a->fils_droit, succ->mot);
            }
        }
    }
    return a;
}

void afficherArbre(T_Arbre a) {
    static char lettre_courante = '\0';
    if (a == NULL) return;
    afficherArbre(a->fils_gauche);

    char lettre = tolower(a->mot[0]);

    if (lettre != lettre_courante) {
        lettre_courante = lettre;
        printf("%c-- %s [%d]\n", toupper(lettre), a->mot, a->nombre_occurences);
    } else {
        printf("    %s [%d]\n", a->mot, a->nombre_occurences);
    }
    afficherArbre(a->fils_droit);
}


int estEquilibreRec(T_Arbre a, bool *equilibre){
    // cas de base : l'arbre est vide ou non équilibré
    if (a == NULL || !equilibre) {
        return 0;
    }
    // récupère la hauteur du sous-arbre de gauche
    int h_gauche = estEquilibreRec(a->fils_gauche, equilibre);
    // récupère la hauteur du sous-arbre droit
    int h_droit = estEquilibreRec(a->fils_droit, equilibre);
    // l'arbre est déséquilibré si la différence absolue entre la hauteur de
    // son sous-arbre gauche et droit est supérieur à 1
    if (abs(h_gauche - h_droit) > 1) {
        *equilibre = false;
    }
    // renvoie la hauteur du sous-arbre enraciné au nœud actuel
    return (h_gauche > h_droit ? h_gauche : h_droit) + 1;
}

bool estEquilibre(T_Arbre a){
  bool equilibre = true;
  estEquilibreRec(a, &equilibre);
  return equilibre;
}

t_mot* transformerArbreRec(T_Arbre a, t_mot *liste, t_mot **queue){
  //parcour infixe afin de construire le lexique dans l'ordre croissant
  if (a == NULL) return liste;
  if (a->fils_gauche!=NULL){
    liste = transformerArbreRec(a->fils_gauche, liste, queue);
    }
    t_mot *nouveauMot = malloc(sizeof(t_mot));
    nouveauMot->mot = malloc(strlen(a->mot) + 1);
    strcpy(nouveauMot->mot, a->mot);
    nouveauMot->nombre_occurences = a->nombre_occurences;
    nouveauMot->suivant = NULL;
    if(liste == NULL){
      liste = nouveauMot;
    }
    if ((*queue) != NULL){
      (*queue)->suivant = nouveauMot;
    }
    *queue = nouveauMot;
    if (a->fils_droit!=NULL){
      liste = transformerArbreRec(a->fils_droit, liste, queue);
    }
    return liste;
}

t_mot *transformerArbre(T_Arbre a){
  t_mot *liste = NULL;
  t_mot *queue = NULL;
  liste = transformerArbreRec(a, liste, &queue);
  return liste;
}



t_pile_arbre creer_pile(T_Arbre a){
  t_pile_arbre new = malloc(sizeof(t_liste_arbre));
  new->sommet = a;
  new->prec = NULL;
  return new;
}



void empiler(t_pile_arbre *p, T_Arbre a){
  t_pile_arbre new= creer_pile(a);
  if(*p!=NULL){
    new->prec = *p;
  }
  *p = new;
}



T_Arbre depiler(t_pile_arbre *p){
  if(*p == NULL){
    return NULL;
  }
  T_Arbre a = (*p)->sommet;
  t_pile_arbre tmp = *p;
  *p=(*p)->prec;
  free(tmp);
  return a;
}

T_Arbre descenteGauche(T_Arbre a, t_pile_arbre *p){
  if (a == NULL) return NULL;
  while (a->fils_gauche!=NULL){
    empiler(p, a);
    a = a->fils_gauche;
  }
  return a;

}

T_Arbre parcourir(T_Arbre a, t_pile_arbre *p){
  if(a->fils_droit == NULL){
    a = depiler(p);
  }else{
    a = descenteGauche(a->fils_droit, p);
  }
  return a;
}



float jaccard(T_Arbre a, T_Arbre b){
  t_pile_arbre pile_a = NULL;
  t_pile_arbre pile_b = NULL;

  T_Arbre tmp_a = descenteGauche(a, &pile_a);
  T_Arbre tmp_b = descenteGauche(b, &pile_b);

  int inter=0;
  int uni=0;

  while (tmp_a != NULL && tmp_b != NULL){
    if(strcmp(tmp_a->mot, tmp_b->mot)==0){
      inter += fmin(tmp_a->nombre_occurences,tmp_b->nombre_occurences);
      uni += fmax(tmp_a->nombre_occurences,tmp_b->nombre_occurences);
      tmp_a = parcourir(tmp_a, &pile_a);
      tmp_b = parcourir(tmp_b, &pile_b);

    }else if(strcmp(tmp_a->mot, tmp_b->mot)<0){
      uni += tmp_a->nombre_occurences;
      tmp_a = parcourir(tmp_a, &pile_a);

    }else{
      uni += tmp_b->nombre_occurences;
      tmp_b = parcourir(tmp_b, &pile_b);
    }

  }
  //finir le parcours de l'arbre non parcouru

  while (tmp_a!=NULL){
    uni += tmp_a->nombre_occurences;
    tmp_a = parcourir(tmp_a, &pile_a);
  }

  while (tmp_b!=NULL){
    uni += tmp_b->nombre_occurences;
    tmp_b = parcourir(tmp_b, &pile_b);
  }

  printf("inter : %d, union : %d",inter,uni);
  return (float)inter/uni;
}



void detruireArbre(T_Arbre a) {
    if (a == NULL) return;
    detruireArbre(a->fils_gauche);
    detruireArbre(a->fils_droit);
    free(a->mot);
    free(a);
}


void detruireListe(t_mot *liste) {
    t_mot *current = liste;
    while (current != NULL) {
        t_mot *temp = current->suivant;
        free(current->mot);
        free(current);
        current = temp;
    }
    liste = NULL;
}
