from objets import Carte,JeuCartes,Player,Paquet
from menu import Menu
from time import sleep
import pygame
pygame.init()

class Game:
    def __init__(self):
        #Games variables
        self.screen = pygame.display.set_mode((1200, 600))
        self.running, self.game, self.inGame, self.end_round, self.bataille = True, False, False, False, False  #Differents etats du jeux
        self.clock = pygame.time.Clock()
        self.round_end_time = pygame.time.get_ticks()

        #Differents etats dans une manche
        self.nbTour, self.playerTour, self.playerWin = 0, 0, -1
        self.batailleIndex = 0

        #Charger les objets
        self.Menu = Menu()
        self.jeuCartes = JeuCartes()
        self.carteEnJeu = []

        #Gerer les differentes positions des cartes, pour faire en sorte quelle soit cote a cote horizontalement lors d'une bataille.
        liste = [x for x in range(26) for _ in range(2)]
        self.pos_carte = [pygame.Rect(530 + 80 * liste[i], 330, 58, 98) if i %2 == 0 else pygame.Rect(530 - 80 * liste[i], 170, 58, 98) for i in range(len(liste))]


        self.win = False

    def event(self):
        #Gestion des evenements
        time = pygame.time.get_ticks()
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                self.running = False

            elif event.type == pygame.KEYDOWN and not self.game:  #Si l'utilisateur entre une touche lors du menu.
                    self.Menu.getPLayerName(event)

            #Gestion de la fin d'une manche.
            if self.end_round and time - self.round_end_time >= 2300:
                self.playerWin, self.playerTour=-1, 0
                self.end_round  = False
                self.round_end_time = time
                #si il n'y pas bataille remettre les cartes en jeux a 0.
                if not self.bataille:
                    self.carteEnJeu = []
                    self.batailleIndex = 0
                self.bataille = False

    def update(self):
        #Deroulement du jeux
        if not self.game and not self.win:
            self.game = self.Menu.lancer()
        elif self.game:
            if not self.inGame: #Debut d'une partie
                self.jeuCartes.shuffle()
                paquet1, paquet2 = Paquet(self.jeuCartes.jeux[:2], (120, 450)), Paquet(self.jeuCartes.jeux[-2:], (1030, 50))
                self.playerEnJeu = (Player(self.Menu.names[0], paquet1), Player(self.Menu.names[1], paquet2))
                self.inGame = True
            else:
                if self.playerEnJeu[self.playerTour].paquet.rect.collidepoint(pygame.mouse.get_pos()) and pygame.mouse.get_pressed()[0] and self.playerTour >= 0: #L'orsque que le joueur a qui c'est le tour appuie sur son jeu.
                    self.carteEnJeu.append(self.playerEnJeu[self.playerTour].tirer())
                    self.playerTour = 1 - self.playerTour

                #Lorsque les deux joueurs ont tirer une carte.
                if not self.end_round and (len(self.carteEnJeu) == 2+self.batailleIndex and len(self.carteEnJeu) !=  0 and not self.bataille ):
                    self.playerTour = -1
                    self.nbTour += 1
                    self.playerWin = 0 if self.carteEnJeu[0 + self.batailleIndex].v > self.carteEnJeu[1 + self.batailleIndex].v else 1 if self.carteEnJeu[0 + self.batailleIndex].v < self.carteEnJeu[1 + self.batailleIndex].v else -2
                    if self.playerWin in (0, 1): #Si il y'a un gagnant.
                        for carte in self.carteEnJeu:
                            self.playerEnJeu[self.playerWin].paquet.ajouter(carte)
                        self.end_round = True
                        self.bataille = False

                    elif self.playerWin == -2: #Bataille !
                        self.bataille = True
                        self.end_round = True
                        self.batailleIndex += 2

                if self.playerEnJeu[0].paquet.taille() == 0 or self.playerEnJeu[1].paquet.taille() == 0:  #Gestion de la fin d'une partie.
                    self.playerWin  = 1 if self.playerEnJeu[1].paquet.taille() == 0 else 2
                    self.win  = True
                    self.game = False
                    self.inGame = False


    def display(self):
        #Gestion de l'affichage
        time = pygame.time.get_ticks()
        self.screen.fill('white')
        if not self.game and not self.win:
            self.Menu.affiche(self.screen)
        elif self.inGame:
            self.Menu.afficheInGame(self.screen, self.playerEnJeu, time, self.playerTour, self.nbTour)
            pygame.draw.rect(self.screen, 'black', self.pos_carte[0], 2)
            pygame.draw.rect(self.screen, 'black', self.pos_carte[1], 2)
            for carte in range(len(self.carteEnJeu)):
                    self.carteEnJeu[carte].affiche(self.screen, self.pos_carte[carte].x, self.pos_carte[carte].y)

            if self.playerWin in (0, 1, -2):
                self.Menu.afficheRound(self.screen, self.playerEnJeu, self.playerWin)
        elif self.win:
            self.Menu.afficheWin(self.screen, self.playerEnJeu[self.playerWin -1])


        pygame.display.flip()

    def run(self):
        while self.running:
            self.event()
            self.update()
            self.display()

            self.clock.tick(120)

game = Game()
game.run()
