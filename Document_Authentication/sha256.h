#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t estado[8];
    uint32_t contador[2];
    uint8_t buffer[64];
} SHA256_CONTEXTO;

void sha256_init(SHA256_CONTEXTO *ctx);
void sha256_atualiza(SHA256_CONTEXTO *ctx, const uint8_t *dados, size_t tam);
void sha256_final(SHA256_CONTEXTO *ctx, uint8_t hash[32]);
void sha256(const uint8_t *dados, size_t tam, uint8_t hash[32]);

#endif
