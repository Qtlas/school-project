#ifndef ABR_H
#define ABR_H

#include <stdbool.h>

// Définition du type de nœud et de l’arbre
typedef struct Noeud {
    char *mot;
    int nombre_occurences;
    struct Noeud *fils_gauche;
    struct Noeud *fils_droit;
} T_Noeud;
typedef T_Noeud* T_Arbre;

struct s_mot {
    char* mot;
    int nombre_occurences;
    struct s_mot* suivant;
};
typedef struct s_mot t_mot;


typedef struct liste_arbre {
    T_Arbre sommet;
    struct liste_arbre* prec;
}t_liste_arbre;



typedef t_liste_arbre* t_pile_arbre;

void toLowerCase(char *str);
T_Arbre trouverMin(T_Arbre a);
int hauteur(T_Arbre a);
void detruireArbre(T_Arbre a);
void detruireListe(t_mot *liste);


T_Arbre creerNoeud(char *mot);
T_Arbre ajouterMot(T_Arbre a, char *mot);
T_Arbre retirerMot(T_Arbre a, char *mot);
void afficherArbre(T_Arbre a);
bool estEquilibre(T_Arbre a);
t_mot *transformerArbre(T_Arbre a);
t_pile_arbre creer_pile(T_Arbre a);
void empiler(t_pile_arbre *p, T_Arbre a);
T_Arbre depiler(t_pile_arbre *p);
T_Arbre descenteGauche(T_Arbre a, t_pile_arbre *p);
T_Arbre parcourir(T_Arbre a, t_pile_arbre *p);
float jaccard(T_Arbre a, T_Arbre b);

#endif
