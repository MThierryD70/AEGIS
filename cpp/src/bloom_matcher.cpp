#include <windows.h>
# include <stdio.h>
#include <string.h>
#include <stdint.h>


//_________________________________________________
// Paramètres du Bloom Filter
// Pour 1 million de signatures, faux positifs ~1%
//_________________________________________________


#define BLOOM_SIZE 9600000 // taille du tableau en bits (~9.6 Mo)
#define BLOOM_BYTES (BLOOM_SIZE / 8)
#define NUM_HASHES 7                // nombre de fonctions de hash


// Tableau de bits global - chargé en RAM au démarrage
static unsigned char bloom[BLOOM_BYTES];
static int bloom_initialized = 0;

//__________________________________________________
// Fonctions de hash internes
// On utilise FNV-1a - rapide et bien distribué
//__________________________________________________

static uint64_t fnv1a (const char* str, uint64_t seed) {
    uint64_t hash = 14695981039346656037ULL ^ seed;
    while(*str){
        hash ^= (unsigned char) (*str++);
        hash *= 1099511628211ULL;
    }
    return hash;
}

// Calcul de l'index de bit pour la fonction de hash i
static uint64_t bloom_hash (const char* value, int i){
    return fnv1a(value,(uint64_t)i * 2654435761ULL) % BLOOM_SIZE;
}

//___________________________________________________
// Opérations sur les bits du tableau
//___________________________________________________
static void set_bit(uint64_t pos){
    bloom[pos / 8] |= (1 << (pos % 8));
}

static int get_bit(uint64_t pos){
    return (bloom[pos / 8] >> (pos % 8)) & 1;
}

//____________________________________________________
// API exportée vers Python
//____________________________________________________

// Initialiser le Bloom Filter (remet tous les bits à 0)
extern "C" __declspec(dllexport)
void bloom_init(){
    memset(bloom, 0, BLOOM_BYTES);
    bloom_initialized = 1;
}


// Ajouter un hash dans le Bloom Filter
extern "C" __declspec(dllexport)
void bloom_add(const char* hash_value){
    if(!bloom_initialized) bloom_init();
    for (int i=0; i<NUM_HASHES; i++){
        set_bit(bloom_hash(hash_value, i));
    }
}

// Vérifier si un hash est probablement dans le filtre
// Retourne 1 = peut-être présent, 0 = définitivement absent
extern "C" __declspec(dllexport)
int bloom_check(const char* hash_value){
    if(!bloom_initialized) return 0;
    for(int i=0; i<NUM_HASHES; i++){
        if(!get_bit(bloom_hash(hash_value, i))){
            return 0; // un bit à 0 = absence avec certitude
        }
    }

    return 1; // tous les bits à 1 = probablemant présent
}

// Returner le nombre de bots à 1 (pour les stats)
extern "C" __declspec(dllexport)
int bloom_count_set_bits(){
    int count = 0;
    for (int i = 0; i<BLOOM_BYTES; i++){
        unsigned char b = bloom[i];
        while(b){
            count += b & 1;
            b >>= 1;
        }
    }
    return count;
}



