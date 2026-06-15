#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tp3.h"

// Fonction pour convertir une chaîne en minuscule
void toLowerCase(char *s) {
    for (int i = 0; s[i]; i++) {
      if (s[i] >= 65 && s[i] <= 90){
        s[i] = s[i] + 32;
      }
    }
}
/* ====== FIN toLowerCase ====== */

// Création d'un nouvel élément
t_mot *creerMot(char *mot) {

    t_mot* new_mot = malloc(sizeof(t_mot));
    if (new_mot == NULL) {
        fprintf(stderr, "Erreur d'allocation mémoire.\n");
        return NULL;
    }

    new_mot->mot = malloc(strlen(mot) + 1);
    if (new_mot->mot == NULL) {
        fprintf(stderr, "Erreur d'allocation mémoire.\n");
        free(new_mot);
        return NULL;
    }

    strcpy(new_mot->mot, mot);
    new_mot->nombre_occurences = 1;
    new_mot->suivant = NULL;

    return new_mot;
}

/* ====== FIN creerMot ====== */

// Ajout d'un mot dans une liste
t_mot *ajouterMot(t_mot *liste, char *mot) {
    //convertir en minuscule
    toLowerCase(mot);

    t_mot *tmp = liste;
    t_mot *prec = NULL;
    while(tmp!= NULL && strcmp(tmp->mot, mot)<0){
        prec = tmp;
        tmp = tmp->suivant;
    }
    //si le mot est déja dans le lexique
    if (tmp!=NULL && strcmp(tmp->mot, mot) == 0){
        tmp->nombre_occurences += 1;
    }else{
        //création d'une structure mot pour stocker le mot dans le lexique
        t_mot *nouveauMot = creerMot(mot);
        //insertion de la structure mot dans le lexique
        //nouveau mot en tete de liste
        if(prec == NULL){
            nouveauMot->suivant = liste;
            liste = nouveauMot;
        }
        //nouveau mot en queue de liste
        else if(tmp == NULL){
            prec->suivant = nouveauMot;
        }
        else{
            prec->suivant = nouveauMot;
            nouveauMot->suivant = tmp;
        }
    }
    return liste;
}

/* ====== FIN ajouterMot ====== */


// Retrait d'une occurence mot d'une liste
t_mot *retirerMot(t_mot *liste, char *mot){
    toLowerCase(mot);

    t_mot *tmp = liste;
    t_mot *prec = NULL;
    while(tmp!= NULL && strcmp(tmp->mot, mot)<0){
        prec = tmp;
        tmp = tmp->suivant;
    }
    //si le mot se trouve dans le lexique,
    if (tmp!=NULL){
        //cas de la supression de la derniere occurence
        if(tmp->nombre_occurences<=1){
            if (tmp!=liste){
                prec->suivant = tmp->suivant;
            }else{
                liste = tmp->suivant;
            }
            free(tmp->mot);
            free(tmp);
        }else{
            tmp->nombre_occurences--;
        }
    } else {
      printf("Le mot n'est pas dans la liste. \n");
    }
    return liste;
}
/* ====== FIN retirerMot ====== */


// Affichage des mots d'un lexique
void afficherMots(t_mot *liste){
  if (liste != NULL){
    t_mot *current = liste;
    char letter = '\0';
    while (current != NULL) {
      if ( current->mot[0] -32 != letter ){
        letter = current->mot[0] - 32;
        printf("%c --- %s [%d]\n", letter, current->mot, current->nombre_occurences);
      } else {
        printf("  --- %s [%d]\n", current->mot, current->nombre_occurences);
      }
      current = current->suivant;
    }
  } else {
    printf("Liste vide.\n");
  }
  printf("\n");
}
/* ====== FIN afficherMots ====== */


// Fusion listes
t_mot *fusionner(t_mot *listeA, t_mot *listeB){
    t_mot *tmp = listeA;
    t_mot *prec;
    t_mot *mem;
    while(listeB!=NULL && tmp!=NULL){
        if(strcmp(tmp->mot, listeB->mot)<0){
            prec=tmp;
            tmp = tmp->suivant;
        }else if(strcmp(tmp->mot, listeB->mot)==0){
            tmp->nombre_occurences += listeB->nombre_occurences;
            mem = listeB;
            listeB = mem->suivant;
            free(mem->mot);
            free(mem);
        }else{
            mem = listeB;
            listeB = mem->suivant;
            mem->suivant=tmp;
            //insertion en tete de liste
            if (tmp == listeA){
                listeA = mem;
            }else{
                prec->suivant = mem;
            }
            tmp = mem;
        }
    }
    if (tmp == NULL){
        if(listeA != NULL){
            prec->suivant = listeB;
            listeB = NULL;
        }else{
            listeA = listeB;
        }
    }
    return listeA;
}
/* ====== FIN fusionner ====== */


// Import d'un fichier de mots dans une liste
t_mot *importerFichier(t_mot *liste) {
    FILE *file = fopen("test.txt", "r");
    if (file == NULL) {
        printf("Le fichier n'existe pas.\n");
        return liste;
    }
    char mot[256];
    while (fgets(mot, sizeof(mot), file)) {
        mot[strcspn(mot, "\n")] = 0;
        liste = ajouterMot(liste, mot);
    }
    fclose(file);
    return liste;
}
/* ====== FIN importerFichier ====== */


// fonction utile pour vider le tampon clavier
void viderBuffer() {
    int c = '0';
    while (c!='\n' && c != EOF) { c = getchar(); }
}
/* ====== FIN viderBuffer ====== */


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
