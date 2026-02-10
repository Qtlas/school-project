from data import asset
import random

class Carte:
    def __init__(self, v, f):
        self.v = v
        self.f = f

    def affiche(self, screen, x, y):
        carte_asset = asset
        screen.blit(carte_asset[self.f][self.v], (x,y))


class JeuCartes:
    def __init__(self):
        self.jeux = [Carte(v, f) for f in  ("pique", 'coeur', "carreau", "trefle") for v in range(0, 13)]

    def shuffle(self):
        random.shuffle(self.jeux)

class Paquet:
    def __init__(self, cartes, pos):
        self.paquet = cartes
        self.img = asset['dos_carte']
        self.rect = self.img.get_rect(topleft=pos)

    def ajouter(self, x):
        self.paquet.insert(0, x)

    def affiche(self, screen):
        screen.blit(self.img, self.rect)

    def taille(self):
        return len(self.paquet)

class Player:
    def __init__(self, nom, paquet):
        self.paquet = paquet
        self.nom = nom

    def tirer(self):
        carteTirer = self.paquet.paquet.pop(len(self.paquet.paquet) - 1)
        return carteTirer
