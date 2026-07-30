#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>

// OpenSSL
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

namespace py = pybind11;

//_________________________________________________________________
// Constantes
//_________________________________________________________________
#define BLOCK_SIZE      65536  
#define BLOOM_SIZE      9600000
#define BLOOM_BYTES     (BLOOM_SIZE / 8)
#define NUM_HASHES      7

//_________________________________________________________________
// Utilitaires internes
//_________________________________________________________________

static std::string bytes_to_hex (const unsigned char* bytes, size_t length) {
    std::ostringstream oss;
    for(size_t i = 0; i<length; i++){
        oss << std::hex << std::setw(2) << std::setfill('0')
            << (int)bytes[i];
    }
    return oss.str();
}

//__________________________________________________________________
// Module Hasher
//__________________________________________________________________

static std::string hash_file (const std::string& filepath, bool use_sha256){
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()){
        throw std::runtime_error("Impossible d'ouvrir : " + filepath);
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = use_sha256 ? EVP_sha256() : EVP_md5();
    EVP_DigestInit_ex(ctx, md, nullptr);

    char buffer[BLOCK_SIZE];
    while(file.read(buffer, BLOCK_SIZE) || file.gcount() > 0){
        EVP_DigestUpdate(ctx, buffer, file.gcount());
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    return bytes_to_hex(hash, hash_len);
}

// Retourner {"md5" : "...", "sha256" : "..."} comme dict Python

py::dict compute_hashes(const std::string& filepath){
    py::dict result;
    result["md5"] = hash_file(filepath, false);
    result["sha256"] = hash_file(filepath, true);
    return result;
}

//__________________________________________________________________
// Module Bloom Filter
//__________________________________________________________________

static unsigned char bloom[BLOOM_BYTES];
static bool bloom_ready = false;

static uint64_t fnv1a(const std::string& str, uint64_t seed){
    uint64_t hash = 14695981039346656037ULL ^ seed;
    for (char c : str){
        hash ^= (unsigned char)c;
        hash *= 1099511628211ULL;
    }
    return hash;
}

static uint64_t bloom_hash(const std::string& value, int i){
    return fnv1a(value, (uint64_t)i * 2654435761ULL) % BLOOM_SIZE;
}

void bloom_init(){
    memset(bloom, 0, BLOOM_BYTES);
    bloom_ready = true;
}

void bloom_add(const std::string& hash_value){
    if (!bloom_ready) bloom_init();
    for (int i = 0; i<NUM_HASHES; i++){
        uint64_t pos = bloom_hash(hash_value, i);
        bloom[pos / 8] |= (1 << (pos % 8));   
    }
}


bool bloom_check(const std::string& hash_value){
    if (!bloom_ready) return false;
    for(int i=0; i< NUM_HASHES; i++){
        uint64_t pos = bloom_hash(hash_value, i);
        if(!((bloom[pos / 8] >> (pos % 8)) & 1)){
            return false;
        }
    }
    return true;
}


void bloom_load(const std::vector<std::string>& hashes){
    bloom_init();
    for (const auto& h : hashes){
        bloom_add(h);
    }
}

int bloom_bit_count(){
    int count = 0;
    for (int i=0; i<BLOOM_BYTES; i++){
        unsigned char b = bloom[i];
        while (b){ count += b & 1; b >>= 1;}
    }
    return count;
}

//________________________________________________________________
// Déclaration du module Python
//________________________________________________________________

PYBIND11_MODULE(aegis_cpp, m){
    m.doc() = "Module C++ haute performance pour AEGIS Antivirus";
    
    // Hasher
    m.def("compute_hashes", &compute_hashes,
        py::arg("filepath"),
        "Calcule MD5 et SHA-256 d'un fichier. Retourne un dict.");
    
        // Bloom Filter
    m.def("bloom_init", &bloom_init,
        "Initialise le Bloom Filter (remet à zéro).");
    
    m.def("bloom_add", &bloom_add,
        py::arg("hash_value"),
        "Ajouter un hash dans le Bloom Filter.");
    
    m.def("bloom_check", &bloom_check,
        py::arg("hash_value"),
        "Vérifier si un hash est probablemant présent. "
        "False = absent avec certitude.");
    
    m.def("bloom_load", &bloom_load,
        py::arg("hashes"),
        "Charger une liste de hashes dans le Bloom Filter en une fois.");
    
    m.def("bloom_bit_count", &bloom_bit_count,
        "Retoune le nombre de bits actifs (pour les stats).");
}





