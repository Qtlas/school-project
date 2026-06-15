#include <stdio.h>
#include <stdlib.h>

#define TAILLE_FILE 255

struct File {
  int tete;
  int queue;
  int tab[TAILLE_FILE];
};

typedef struct File File;

File* creer_file(){
  File *file = malloc(sizeof(File));
  file->tete = 0;
  file->queue = 0;
  return file;
}

int file_vide(File *file){
  return file->queue == file->tete;
}

int file_pleine(File *file) {
  return file->tete == (file->queue + 1) % TAILLE_FILE;
}

void afficher_file(File *file) {
  printf("[");
  for (int i=file->tete; i<file->queue; i++){
    printf(" %d ", file->tab[i]);
  }
  printf("]\n");
}

void enfiler(File *file, int v){
  if (file_pleine(file)){
    printf("La file est pleine !\n");
  } else {
    file->tab[file->queue] = v;
    file->queue = (file->queue+1)%TAILLE_FILE;
  }
}

int defiler(File *file){
  if (file_vide(file)){
    printf("File vide\n");
    return 0;
  }
  int v = file->tab[file->tete];
  file->tete = (file->tete+1)%TAILLE_FILE;
  return v;
}

int main() {
  File *file = creer_file();

  printf("La file est : %s\n", file_vide(file) ? "vide" : "n'est pas vide");
  printf("La file est : %s\n\n", file_pleine(file) ? "pleine" : "n'est pas pleine");

  for (int i=1; i<=10; i++) enfiler(file, i);
  afficher_file(file);
  defiler(file);
  afficher_file(file);
  return 0;
}
