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

#define TAMANHO_BLOCO_ENTRADA 16 // bytes por bloco
#define DIMENSAO_ESTADO 4 // porque a matriz do estado é 4x4 bytes

// Nº  de rounds para cada tipo de chave
// Nk -> n° de palavras de 32 bits na chave original
#define NK_128 4    // 4 x 32 = 128 bits -> 10 rodadas
#define NK_192 6   // 6 x 32 = 192 bits -> 12 rodadas
#define NK_256 8  // 8 x 32 = 256 bits -> 14 rodadas

// Nr -> n° de rodadas  = Nk + 6
#define NR(nk) ((nk)+6) // macro: Nr a partir do Nk

// Key Schedule produz (Nr + 1) subchaves de 128 bits cada.
// Máximo = AES-256 -> 14 + 1 = subchaves -> 15 x 16 = 240 bytes

#define TAM_MAX_CHAVE_EXPANDIDA 240

// Constantes MixColumns
#define GF_POLINOMIO_IRREDUTIVEL 0x1B
#define GF_TRANSFORMACAO_AFIM 0x63

// Constantes do Key Schedule 
// RCON (Round Constant) são constantes 




