#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "abr.h"

void viderBuffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

int main() {
    T_Arbre a1 = NULL, a2 = NULL;
    t_mot* l1=NULL, *l2=NULL;
    char choixMenu;

    do {
        printf("\n========================================");
        printf("\n  [1] Afficher un arbre");
        printf("\n  [2] Ajouter un mot dans un arbre");
        printf("\n  [3] Retirer un mot d'un arbre");
        printf("\n  [4] Vérifier si un arbre est équilibré");
        printf("\n  [5] Transformer un arbre en liste chainee");
        printf("\n  [6] Calculer l'indice de Jaccard entre a1 et a2");
        printf("\n  [7] Quitter");
        printf("\n========================================");
        printf("\nVotre choix : ");
        choixMenu = getchar();
        viderBuffer();

        char mot[256];
        int num;

        switch (choixMenu) {
            case '1':
                printf("Quel arbre afficher ? (1 ou 2) : ");
                scanf("%d", &num);
                viderBuffer();
                printf("\nContenu de l'arbre %d :\n", num);
                if (num == 1)
                    afficherArbre(a1);
                else if (num == 2)
                    afficherArbre(a2);
                else
                    printf("Choix invalide.\n");
                break;

            case '2':
                printf("Dans quel arbre ajouter un mot ? (1 ou 2) : ");
                scanf("%d", &num);
                viderBuffer();
                printf("Mot à ajouter : ");
                fgets(mot, sizeof(mot), stdin);
                mot[strcspn(mot, "\n")] = '\0';
                if (num == 1)
                    a1 = ajouterMot(a1, mot);
                else if (num == 2)
                    a2 = ajouterMot(a2, mot);
                else
                    printf("Choix invalide.\n");
                break;

            case '3':
                printf("Dans quel arbre retirer un mot ? (1 ou 2) : ");
                scanf("%d", &num);
                viderBuffer();
                printf("Mot à retirer : ");
                fgets(mot, sizeof(mot), stdin);
                mot[strcspn(mot, "\n")] = '\0';
                toLowerCase(mot);
                if (num == 1)
                    a1 = retirerMot(a1, mot);
                else if (num == 2)
                    a2 = retirerMot(a2, mot);
                else
                    printf("Choix invalide.\n");
                break;

            case '4':
                printf("Quel arbre tester ? (1 ou 2) : ");
                scanf("%d", &num);
                viderBuffer();
                if (num == 1)
                    printf("\nArbre 1 %s équilibré.\n", estEquilibre(a1) ? "est" : "n'est pas");
                else if (num == 2)
                    printf("\nArbre 2 %s équilibré.\n", estEquilibre(a2) ? "est" : "n'est pas");
                else
                    printf("Choix invalide.\n");
                break;

          case '5':
              printf("Quel arbre transformer en liste ? (1 ou 2) : ");
              scanf("%d", &num);
              viderBuffer();
              if (num == 1){
                l1 = transformerArbre(a1);
                printf("\nArbre 1 transformer en liste dans liste 1");
              }
              else if (num == 2){
                l2 = transformerArbre(a2);
                printf("\nArbre 2 transformer en liste dans liste 2");
              }
              else
                  printf("Choix invalide.\n");
              break;

            case '6': {
                float indiceJaccard = jaccard(a1, a2);
                printf("\nIndice de Jaccard entre a1 et a2 : %.3f\n", indiceJaccard);
                break;
            }

            case '7':
                detruireArbre(a1);
                detruireArbre(a2);
                detruireListe(l1);
                detruireListe(l2);
                printf("\n\n*** FIN DU PROGRAMME ***\n");
                break;

            default:
                printf("Choix invalide.\n");
        }
    } while (choixMenu != '7');


    return 0;
}
