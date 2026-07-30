#include <windows.h>
#include <stdio.h>
#include <string.h>

// OpenSSL
#include <openssl/md5.h>
#include <openssl/sha.h>

// Taille de lecture par blocs (64 Ko — même logique que Python)
#define BLOCK_SIZE 65536

// Convertir des octets binaires en chaîne hexadécimale
static void bytes_to_hex(
    const unsigned char* bytes,
    size_t length,
    char* output
) {
    for (size_t i = 0; i < length; i++) {
        sprintf(output + (i * 2), "%02x", bytes[i]);
    }
    output[length * 2] = '\0';
}

// Calculer le MD5 d'un fichier
// Retourner 1 si succès, 0 si erreur
extern "C" __declspec(dllexport)
int compute_md5(const char* filepath, char* output) {
    FILE* file = fopen(filepath, "rb");
    if (!file) return 0;

    MD5_CTX ctx;
    MD5_Init(&ctx);

    unsigned char buffer[BLOCK_SIZE];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE, file)) > 0) {
        MD5_Update(&ctx, buffer, bytes_read);
    }
    fclose(file);

    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_Final(hash, &ctx);
    bytes_to_hex(hash, MD5_DIGEST_LENGTH, output);
    return 1;
}

// Calculer le SHA-256 d'un fichier
extern "C" __declspec(dllexport)
int compute_sha256(const char* filepath, char* output) {
    FILE* file = fopen(filepath, "rb");
    if (!file) return 0;

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    unsigned char buffer[BLOCK_SIZE];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE, file)) > 0) {
        SHA256_Update(&ctx, buffer, bytes_read);
    }
    fclose(file);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);
    bytes_to_hex(hash, SHA256_DIGEST_LENGTH, output);
    return 1;
}


