/* /\/\/\ ADVANCED ENCRYPTION STANDARD /\/\/\ */

// AES é uma cifra de bloco simétrica, ou seja, um bloco de dados de 128 bits (16 bytes) é embaralhada de forma reversível
// usando uma chave secreta.
// Por ser simétrica, a chave encripta e decripta.

// Ela funciona em rodadas que se repetem conforme o tamanho da chave da entrada.

#include <stdint.h>

// CONSTANTES

#define BITS_POR_BYTES 8
#define TAMANHO_BLOCO_AES 16 // 16 bytes, 128 bits
#define AES_16_BYTES_KEY 16
