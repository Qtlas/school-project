import pygame
import sys

#pygame Initialisation
pygame.init()



class Hanoi:

    def __init__(self, screen, n):
        self.screen = screen
        self.screenLargeur = 800
        self.screenHauteur = 600

        #Configuration des tours et des disques
        self.tourTaille = 200
        self.tourLargeur = 15
        self.disqueHauteur = 20

        tour_a = [disque for disque in range(n, 0, -1)]
        tour_b = []
        tour_c = []

        self.tours = {
            'A': tour_a,
            'B': tour_b,
            'C': tour_c
        }

        #Couleurs en RGB
        self.BROWN = (139,69,19)
        self.GREEN = (0, 255, 0)

    def drawTours(self):
        """

        Methode qui va dessiner les tours et pour chaque tour dessiner les disques qui lui sont associer.

        """
        x = 200 #Position en x de la premiere tour
        for tour,n in self.tours.items():  #Boucle sur les tours
            pygame.draw.rect(self.screen, self.BROWN, (x-self.tourLargeur//2, self.screenHauteur - self.tourTaille, self.tourLargeur, self.tourTaille)) #Dessiner les tourss

            for j, disque in enumerate(n):  #Deuxiemme boucle sur les disques
                disqueLargeur = 20* disque #Largeur des disques fonction de n
                y = self.screenHauteur - (j + 1) * 20
                pygame.draw.rect(self.screen, self.GREEN, (x - disqueLargeur // 2, y, disqueLargeur, self.disqueHauteur), border_radius=4)  #Dessiner les disque

            x += 200  #Incrementer pour l'espacement entre les tours.


    def Solvehanoi(self, n, tourDebut, tourArrive, tourInter):
        """

        Methode qui resoudre les tours d'hanoi.

        n -> int
        tourDebut,>tourArrive,tourInter -> str

        """

        if n > 0:  #Cas de base
            self.Solvehanoi(n - 1, tourDebut, tourInter, tourArrive)

            #Deplacer le disque entre les listes du dictionnaire self.tours
            disqueMove = self.tours[tourDebut].pop()
            self.tours[tourArrive].append(disqueMove)

            #Affichage des tours
            self.screen.fill((255, 255, 255))
            self.drawTours()
            pygame.display.flip()
            pygame.time.delay(500)

            self.Solvehanoi(n - 1, tourInter, tourArrive, tourDebut)
