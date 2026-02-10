import pygame
pygame.init()


class Menu:
    def __init__(self):
        self.police = [pygame.font.Font("Assets/Font/Gameplay.ttf", 50), pygame.font.Font("Assets/Font/Gameplay.ttf", 20), pygame.font.Font("Assets/Font/Gameplay.ttf", 15)]

        self.start_button_image = pygame.transform.scale(pygame.image.load("Assets/Menu/startButton.png").convert_alpha(), (170, 120))
        self.start_button_rect = self.start_button_image.get_rect(topleft=(515, 430))

        self.player1_rect = pygame.Rect(450, 270, 300, 50)
        self.player2_rect = pygame.Rect(450, 370, 300, 50)

        self.names, self.i = ["", ""], 0
        self.time_upd, self.could = pygame.time.get_ticks(), 300


    def affiche(self, screen):
        screen.blit(self.police[0].render("Bataille !", True, 'black'), (450, 40))
        screen.blit(self.police[1].render("Bienvenue dans ce jeu de Bataille où règne la violence.", True, 'black'), (270, 140))
        screen.blit(self.police[1].render("Choisissez le nom de votre armée, armez-vous, puis bataillez !", True, 'black'), (240, 170))

        pygame.draw.rect(screen, (0, 0, 0), self.player1_rect, 2)
        pygame.draw.rect(screen, (0, 0, 0), self.player2_rect, 2)

        screen.blit(self.police[1].render(self.names[0], True, 'black'),  (self.player1_rect.x + 8, self.player1_rect.y + 8))
        screen.blit(self.police[1].render(self.names[1], True, 'black'),  (self.player2_rect.x + 8, self.player2_rect.y + 8))

        screen.blit(self.start_button_image, self.start_button_rect)

    def afficheInGame(self, screen, playerEnJeu, time, playerTour, nbTour):
        for player in range(len(playerEnJeu)):
            playerEnJeu[player].paquet.affiche(screen)
            screen.blit(self.police[2].render(playerEnJeu[player].nom, True, 'black'), (playerEnJeu[player] .paquet.rect.x + 5, playerEnJeu[player].paquet.rect.y - 20))
            screen.blit(self.police[2].render(str(playerEnJeu[player].paquet.taille()), True, 'black'), (playerEnJeu[player].paquet.rect.x + 15, playerEnJeu[player].paquet.rect.y + 110))
            screen.blit(self.police[0].render(str(nbTour), True, 'black'), (40, 40))
            if time - self.time_upd >= self.could and player == playerTour:
                pygame.draw.rect(screen, 'yellow',  playerEnJeu[player].paquet.rect, 2)
                if time - self.time_upd > self.could +1200:
                    self.time_upd =  time

    def afficheRound(self, screen, playerEnJeu, playerWin):
        if playerWin >= 0:
            screen.blit(self.police[1].render(f"{playerEnJeu[playerWin].nom} a gagner la manche !", True, 'black'), (400, 30))
        else:
            screen.blit(self.police[1].render( "Bataille !", True, 'black'), (400, 30))


    def afficheWin(self, screen, playerWin):
        screen.blit(self.police[0].render(f"{playerWin.nom} a gagner la partie !", True, 'black'), (200, 200))

    def lancer(self):
        return self.start_button_rect.collidepoint(pygame.mouse.get_pos()) and pygame.mouse.get_pressed()[0] and all(len(name) >= 1 for name in self.names) and self.names[0] != self.names[1]


    def getPLayerName(self, event):
        self.i = 0 if pygame.Rect.collidepoint(self.player1_rect, pygame.mouse.get_pos()) else 1 if pygame.Rect.collidepoint(self.player2_rect, pygame.mouse.get_pos()) else self.i

        if event.key == pygame.K_BACKSPACE:
            self.names[self.i] = self.names[self.i][:-1]
        else:
            if len(self.names[self.i]) < 7:
                self.names[self.i] += event.unicode
