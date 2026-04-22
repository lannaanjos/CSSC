#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <stddef.h>

void hmac_sha256(const uint8_t *chave, size_t tam_chave, const uint8_t *mensagem, size_t tam_msg, uint8_t saida[32]);

#endif
