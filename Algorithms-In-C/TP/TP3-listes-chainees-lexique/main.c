#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tp3.h"

int main() {
    t_mot *l1 = NULL, *l2 = NULL;
    char choixMenu;

    do {
        printf("\n========================================");
        printf("\n  [1] Afficher un lexique");
        printf("\n  [2] Ajouter un mot dans un lexique");
        printf("\n  [3] Retirer un mot d'un lexique");
        printf("\n  [4] Fusionner deux lexiques");
        printf("\n  [5] Charger un fichier dans un lexique");
        printf("\n  [6] Quitter");
        printf("\n========================================");
        printf("\nVotre choix : ");
        choixMenu = getchar();
        viderBuffer();

        char mot[256];
        int num;
        switch (choixMenu) {
            case '1':
                printf("Quel lexique afficher ? (1 ou 2) : ");
                scanf("%d", &num);
                viderBuffer();
                printf("\nContenu du lexique %d :\n", num);
                if (num == 1)
                    afficherMots(l1);
                else if (num == 2)
                    afficherMots(l2);
                else
                    printf("Choix invalide.\n");
                break;

            case '2':
                printf("Dans quel lexique ajouter un mot ? (1 ou 2) : ");
                scanf("%d", &num);
                viderBuffer();
                printf("Mot à ajouter : ");
                fgets(mot, sizeof(mot), stdin);
                mot[strcspn(mot, "\n")] = '\0';
                if (num == 1)
                    l1 = ajouterMot(l1, mot);
                else if (num == 2)
                    l2 = ajouterMot(l2, mot);
                else
                    printf("Choix invalide.\n");
                break;

            case '3':
                printf("Dans quel lexique retirer un mot ? (1 ou 2) : ");
                scanf("%d", &num);
                viderBuffer();
                printf("Mot à retirer : ");
                fgets(mot, sizeof(mot), stdin);
                mot[strcspn(mot, "\n")] = '\0';
                if (num == 1)
                    l1 = retirerMot(l1, mot);
                else if (num == 2)
                    l2 = retirerMot(l2, mot);
                else
                    printf("Choix invalide.\n");
                break;

            case '4':
                printf("Fusion de l2 dans l1...\n");
                l1 = fusionner(l1, l2);
                l2 = NULL;
                printf("Fusion terminer.\n");
                break;

            case '5':
                printf("Dans quel lexique charger le fichier ? (1 ou 2) : ");
                scanf("%d", &num);
                viderBuffer();
                if (num == 1)
                    l1 = importerFichier(l1);
                else if (num == 2)
                    l2 = importerFichier(l2);
                else
                    printf("Choix invalide.\n");
                break;
          case '6':
            detruireListe(l1);
            detruireListe(l2);
            break;

          default:
            printf("Choix invalide.\n");
        }
    } while (choixMenu != '6');


    printf("\n\n*** FIN DU PROGRAMME ***\n");

    return 0;
}
