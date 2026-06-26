#include <stdio.h>
#include "hashmap.h"



int main() {
    printf("Hashmap in C ! (using chain method))\n");
    hashmap *map = initHashMap();
    char keys[][10] = {"lisa<3", "tom", "leila", "hayse", "kaneki", "juzo", "yo", "wills", "bouzeuh"};
    float value[] = {10.0, 8.7, 19.1, 11.8, 7.8, 9.87, 8.2, 9.7, 17.9};

    for (int i=0; i < sizeof(value) / sizeof(int); i++) {
        insertHashMap(map, keys[i], value[i]);
        printf("Load factor : %f\n", loadFactor(map->capacity, map->length));
    }
    printHashMap(map);
    freeHashMap(map);
    return 0;
}