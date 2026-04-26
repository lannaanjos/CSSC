
// pbkdf2-hmac-sha256 -> deriva uma chave AES256 (32 bytes) a partir de uma senha humana.
//
// entradas: senha, salt, iterações e comprimento desejado (q vai ser 32 bytes)
// saída: chave de 32 bytes.
//
#include <stdio.h>
#include <string.h>
#include "pbkdf2.h"
#include "hmac.h"

void pbkdf2_hmac_sha256(const uint8_t *senha, size_t tam_senha,
                        const uint8_t *salt, size_t tam_salt,
                        uint32_t iteracoes,
                        uint8_t *chave_derivada, size_t tam_chave){

  uint32_t bloco = 1;
  uint32_t i;
  size_t posicao = 0;
  uint8_t salt_cont[128]; // salt + 4 bytes do contador
  uint8_t U[32]; // result hmac atual
  uint8_t T[32]; // xor acumulado

  while (posicao < tam_chave) {
    // concat salt e contador
    memcpy(salt_cont, salt, tam_salt);
    salt_cont[tam_salt] = (bloco >> 24) & 0xFF;
    salt_cont[tam_salt + 1] = (bloco >> 16) & 0xFF;
    salt_cont[tam_salt + 2] = (bloco >> 8) & 0xFF;
    salt_cont[tam_salt + 3] = bloco & 0xFF;

    //u1 = hmac(senha, salt cont)
    hmac_sha256(senha, tam_senha, salt_cont, tam_salt + 4, U);
    memcpy(T, U, 32);

    // u2 .. Ui iter, cada um xor acumula em T.
    for (i = 1; i < iteracoes; i++){
      hmac_sha256(senha, tam_senha, U, 32, U);
      for (int j = 0; j < 32; j++){
        T[j] ^= U[j];
      }
    }

    // copia T p chave derivada 
    size_t resto_bytes = tam_chave - posicao;
    if (resto_bytes >= 32){
      memcpy(chave_derivada + posicao, T, 32);
      posicao += 32;
    } else {
      memcpy(chave_derivada + posicao, T, resto_bytes);
      posicao = tam_chave;
    }

    bloco++;

  }
}
