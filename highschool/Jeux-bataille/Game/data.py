import pygame
pygame.init()

screen = pygame.display.set_mode((1, 1))

def get_image(idle, frame, taille, hauteur, verti):
        """
        Recupere une image contenant une liste de cartes et renvoie une image d'une seule carte.
        """
        image = pygame.Surface((taille, hauteur)).convert_alpha()
        image.blit(idle, (0, 0), ((frame * taille), 0, taille, hauteur))
        image = pygame.transform.flip(image, verti, False)
        image = pygame.transform.scale(image, (60, 100))
        image.set_colorkey([0, 0, 0])  #Fond transparent.
        return image  

famille_list =  ("coeur", "carreau", "trefle", "pique")
famille_img = [pygame.image.load(f"Assets/Carte/{i}.png").convert_alpha() for i in famille_list]
asset = {famille: [get_image(famille_img, l, 108, 133, False) for l in range(0, 13)] for famille, famille_img in zip(famille_list, famille_img)}
asset['dos_carte'] = pygame.transform.scale(pygame.image.load(f"Assets/Carte/dos.png").convert_alpha(), (60, 100))
