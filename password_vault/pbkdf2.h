#ifndef PBKDF2_H
#define PBKDF2_H

#include <stdint.h>
#include <stddef.h>

void pbkdf2_hmac_sha256(const uint8_t *senha, size_t tam_senha,
                        const uint8_t *salt, size_t tam_salt,
                        uint32_t iteracoes,
                        uint8_t *chave_derivada, size_t tam_chave);

#endif
