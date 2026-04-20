#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

// constantes
#define TAMANHO_BYTES_ENTRADA 16
#define NK_256 8
#define TAM_MAX_CHAVE_EXPANDIDA 240

// protótipos
void gerar_sbox(void);
void expansao_chave(const uint8_t *chave, uint8_t subchaves[TAM_MAX_CHAVE_EXPANDIDA], int nk);
void cifragem(const uint8_t entrada_original[TAMANHO_BYTES_ENTRADA],
              const uint8_t subkeys[TAM_MAX_CHAVE_EXPANDIDA],
              uint8_t cifra[TAMANHO_BYTES_ENTRADA],
              int nk);
void decifragem(const uint8_t cifra[TAMANHO_BYTES_ENTRADA],
                const uint8_t subkeys[TAM_MAX_CHAVE_EXPANDIDA],
                uint8_t entrada_original[TAMANHO_BYTES_ENTRADA],
                int nk);

#endif
