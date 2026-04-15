/* /\/\/\ ADVANCED ENCRYPTION STANDARD /\/\/\ */

// AES é uma cifra de bloco simétrica, ou seja, um bloco de dados de 128 bits (16 bytes) é embaralhada de forma reversível
// usando uma chave secreta.
// Por ser simétrica, a chave encripta e decripta.

// Ela funciona em rodadas que se repetem conforme o tamanho da chave da entrada.

#include <stddef.h>
#include <stdint.h> // -> uinbt8_t, uint32_t
#include <string.h> // -> memcpy, memset
#include <stdio.h>
#include <stdlib.h>

// CONSTANTES

#define TAMANHO_BYTES_ENTRADA 16 // bytes por bloco
#define DIMENSAO_ESTADO 4 // porque a matriz do estado é 4x4 bytes

// Nº  de rounds para cada tipo de chave
// Nk -> n° de palavras de 32 bits na chave original
#define NK_128 4    // 4 x 32 = 128 bits -> 10 rodadas
#define NK_192 6   // 6 x 32 = 192 bits -> 12 rodadas
#define NK_256 8  // 8 x 32 = 256 bits -> 14 rodadais

// Nr -> n° de rodadas  = Nk + 6
#define NR(nk) ((nk)+6) // macro: Nr a partir do Nk

// Key Schedule produz (Nr + 1) subchaves de 128 bits cada.
// Máximo = AES-256 -> 14 + 1 = subchaves -> 15 x 16 = 240 bytes
#define TAM_CHAVE_128 176     // (10 + 1) x 16 = 176
#define TAM_CHAVE_192 208     // (12 + 1) x 16 = 208
#defime TAM_CHAVE_256 240     // (14 + 1) x 16 = 240
#define TAM_MAX_CHAVE_EXPANDIDA 240 // max possivel 

// Constantes MixColumns
// x⁸ + x⁴ + x³ + x + 1 = 0x11B
// usa-se 0x11B porque descartamos o bit x⁸
#define GF_POLINOMIO_IRREDUTIVEL 0x1B

#define GF_TRANSFORMACAO_AFIM 0x63

// Constantes do Key Schedule 
// RCON (Round Constant) são constantes usadas na expansão de chave para diferenciar cada rodada 
// são potências de 2 em GF(2⁸) rcon[i] = 2^(i-1)
// como o aes256 usat até 7 rodadas de expansõa, usamos 10 valores para cobrir tudo tranquilamente

static const uint8_t RCON[10] = {
  0x01, 0x02, 0x04, 0x08, 0x10,
  0x20, 0x40, 0x80, 0x1B, 0x36
};






