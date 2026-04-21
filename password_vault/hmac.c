#include "hmac.h"
#include "sha256.h"
#include <string.h>

#define BLOCO_BYTES 64

void hmac_sha256(const uint8_t *chave, size_t tam_chave, const uint8_t *mensagem, size_t tam_msg, uint8_t saida[32]){
  uint8_t key_ipad[BLOCO_BYTES]; // chave XOR 0x36. primeiro bloco do hash interno.
  uint8_t key_opad[BLOCO_BYTES]; // chave xor 0x5c. primeiro bloco do hash externo.
  uint8_t hash_interno[32];
  SHA256_CONTEXTO ctx;
  size_t i;

  // /\/\ 1. TRATAMENTO DA CHAVE 
  // se chave > 64 bytes, hasheia p 32 e dps preenche com zeros até 64 dnv.

  uint8_t chave_tratada[BLOCO_BYTES];

  if (tam_chave > BLOCO_BYTES){
    sha256(chave, tam_chave, chave_tratada);

    // preenche resto c zeros
    for (i = 32; i < BLOCO_BYTES; i++){
      chave_tratada[i] = 0;
    }
  } else {
    // cabe no buffer
    memcpy(chave_tratada, chave, tam_chave);
    for (i = tam_chave; i < BLOCO_BYTES; i++){
      chave_tratada[i] = 0;
    }
  }

  // /\/\ 2. CALCULAR K XOR IPAD E K XOR OPED 
  // ipad = 0x36 rpt, opad = 0x5C rpt

  for (i = 0; i < BLOCO_BYTES; i++){
    key_ipad[i] = chave_tratada[i] ^ 0x36;
    key_opad[i] = chave_tratada[i] ^ 0x5C;
  }

  // /\ 3. H((K XOR IPAD) || MSG)

  sha256_init(&ctx);
  sha256_atualiza(&ctx, key_ipad, BLOCO_BYTES);
  sha256_atualiza(&ctx, mensagem, tam_msg);
  sha256_final(&ctx, hash_interno);

  // /\ 4. H((K xor OPAD) || resultado anterior)

  sha256_init(&ctx);
  sha256_atualiza(&ctx, key_opad, BLOCO_BYTES);
  sha256_atualiza(&ctx, hash_interno, 32);
  sha256_final(&ctx, saida);
}
