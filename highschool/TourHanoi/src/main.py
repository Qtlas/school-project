import pygame
import sys
from hanoiSolver import Hanoi

#Initialisation  pygame
pygame.init()

class Game:

    def __init__(self):
        self.screen = pygame.display.set_mode((800, 600))  #Initialisation ecran
        self.clock = pygame.time.Clock()

        button_info = {
            'Start': {'path': 'Img/startButton.png', 'size': (150, 100), 'position': (400, 400)},
            'Retry': {'path': 'Img/retryButton.png', 'size': (100, 75), 'position': (400, 200)},
            'Back': {'path': 'Img/backButton.png', 'size': (100, 75), 'position': (60, 40)}
        }

        self.button = {}

        for button_name, info in button_info.items():
            button_image = pygame.transform.scale(pygame.image.load(info['path']).convert_alpha(), info['size'])  #Redimensionner l'image
            button_rect = button_image.get_rect() #Initialisation rectange image par rappport a la taille image

            button_rect.center = info['position']  #Centrer l'image a la position donner

            self.button[button_name] = {
                'image': button_image,
                'rect': button_rect
            }

            self.police = [pygame.font.SysFont("firacode", 50), pygame.font.SysFont("firacode", 20)] #Liste de police d'ecriture

            self.BLACK = (0,0,0)
            self.inputBox = pygame.Rect(570, 230, 100, 40)

            #Conditions pour gerer la boucle de jeu,lancement,resolution du jeu.
            self.running = True
            self.lunch = False
            self.solve = False


            self.inputText = ""
            self.n = int()


    def Menu(self):
        """

        Methode qui va gerer le texte,bouttons du menu.

        """

        #List de textes content des tuples (texte, police, position)
        textes = [
        ("Tour Hanoi Resolver", self.police[0], (110, 50)),
        (self.inputText, self.police[1], (self.inputBox.x + 7, self.inputBox.y + 7)),
        ("Entrez le nombre de disque(s) :", self.police[1], (200, self.inputBox.y + 10))
        ]

        #Affichage des textes
        for texte, font, position in textes:
            texte_rendu = font.render(texte, 1, self.BLACK)
            self.screen.blit(texte_rendu, position)

        self.screen.blit(self.button['Start']['image'], self.button['Start']['rect'])
        pygame.draw.rect(self.screen, self.BLACK, self.inputBox, 2)


        if self.button['Start']['rect'].collidepoint(pygame.mouse.get_pos()) and pygame.mouse.get_pressed()[0] and self.n > 0:  #Condition qui gere le lancement du jeu
            self.lunch = True

    def reLunch(self):
        """

        Methode qui va gerer les bouttons apres executions du jeu.

        """
        #Afficher les bouttons
        self.screen.blit(self.button['Retry']['image'], self.button['Retry']['rect'])
        self.screen.blit(self.button['Back']['image'], self.button['Back']['rect'])

        if self.button['Retry']['rect'].collidepoint(pygame.mouse.get_pos()) and pygame.mouse.get_pressed()[0]: #Condition qui gere le relancement du jeu
            self.solve = False

        elif self.button['Back']['rect'].collidepoint(pygame.mouse.get_pos()) and pygame.mouse.get_pressed()[0]: #Condition qui gere le retour au menu principal
            self.lunch = False
            self.solve = False


    def enterN(self, event):
        """

        Methode qui va gerer l'entree utilisateur du nombre de disque(s)
        event -> class d'evenement relatif au clavier


        """

        if event.key == pygame.K_RETURN:
            print("N = ", self.inputText)
            self.n = int(self.inputText)

        elif event.key == pygame.K_BACKSPACE:
            self.inputText = self.inputText[:-1]

        else:
            if event.unicode.isdigit():
                nb = int(event.unicode)
                if len(self.inputText) < 2:
                    self.inputText += str(nb)


    def run(self):
        """

        Methode principal qui constitue la boucle principal, et gere la structure du jeu.

        """
        while self.running:  #Boucle de jeu

            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    self.running = False

                elif event.type == pygame.KEYDOWN and not self.lunch:
                    self.enterN(event)

            #Gestion du lancement et resolution du jeu
            if self.lunch:
                if not self.solve:
                    pygame.time.delay(100)
                    #Lancer resolution
                    self.hanoi = Hanoi(self.screen, self.n)
                    self.hanoi.Solvehanoi(self.n, 'A', 'C', 'B')
                    self.solve = True

                self.reLunch()
                pygame.time.delay(75)


            else:
                self.screen.fill((255, 255, 255))   #Mettre le fond en blanc
                self.Menu()

            pygame.display.flip()  #Mise a jour de l'ecran
            self.clock.tick(60)  #Limiter les FPS a 60


game = Game()
game.run()
