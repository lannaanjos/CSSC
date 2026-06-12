// /\/\/\ sha256_teste.c
// testes da implementação SHA-256
// vetores oficiais NIST + casos limite

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "sha256.h"

// /\ AUX
// converte hash de 32 bytes p string hex de 64 chars
static void hash_para_hex(const uint8_t hash[32], char buf[65]){
  int i;
  for (i = 0; i < 32; i++){
    sprintf(buf + i * 2, "%02x", hash[i]);
  }
  buf[64] = '\0';
}

// compara hash calculado com esperado
// retorna 1 em sucesso, 0 em falha
static int verifica(const char *nome, const uint8_t hash[32], const char *esperado){
  char calculado[65];
  hash_para_hex(hash, calculado);

  if (strcmp(calculado, esperado) == 0){
    printf("[SUCESSO] %s\n", nome);
    printf("          %s\n\n", calculado);
    return 1;
  } else {
    printf("[ATENCAO] %s\n", nome);
    printf("  calculado : %s\n", calculado);
    printf("  esperado  : %s\n\n", esperado);
    return 0;
  }
}

// /\/\/\ TESTES
// vetor 1: string vazia
// fonte: NIST FIPS 180-4
static int teste_vazio(void){
  uint8_t hash[32];
  sha256((const uint8_t *)"", 0, hash);
  return verifica(
    "string vazia \"\"",
    hash,
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  );
}

// vetor 2: "abc"
// fonte: NIST FIPS 180-4
static int teste_abc(void){
  uint8_t hash[32];
  sha256((const uint8_t *)"abc", 3, hash);
  return verifica(
    "\"abc\"",
    hash,
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  );
}

// vetor 3: string longa que força múltiplos blocos de 512 bits
// força o padding a estourar p um segundo bloco
// fonte: NIST FIPS 180-4
static int teste_multibloco(void){
  const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  uint8_t hash[32];
  sha256((const uint8_t *)msg, strlen(msg), hash);
  return verifica(
    "string longa multi-bloco (56 bytes, NIST)",
    hash,
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
  );
}

// vetor 4: chamadas incrementais vs chamada única
// garante que o resultado é idêntico independente de como os dados chegam
// divide "abcdef" em três chamadas: "ab", "cd", "ef"
static int teste_incremental(void){
  uint8_t hash_unico[32];
  uint8_t hash_incremental[32];
  SHA256_CONTEXTO ctx;
  char hex_unico[65];
  char hex_incremental[65];

  // chamada única
  sha256((const uint8_t *)"abcdef", 6, hash_unico);

  // chamadas incrementais: "ab" + "cd" + "ef"
  sha256_init(&ctx);
  sha256_atualiza(&ctx, (const uint8_t *)"ab", 2);
  sha256_atualiza(&ctx, (const uint8_t *)"cd", 2);
  sha256_atualiza(&ctx, (const uint8_t *)"ef", 2);
  sha256_final(&ctx, hash_incremental);

  hash_para_hex(hash_unico,       hex_unico);
  hash_para_hex(hash_incremental, hex_incremental);

  if (strcmp(hex_unico, hex_incremental) == 0){
    printf("[SUCESSO] incremental (\"ab\"+\"cd\"+\"ef\" == \"abcdef\")\n");
    printf("          %s\n\n", hex_unico);
    return 1;
  } else {
    printf("[ATENCAO] incremental (\"ab\"+\"cd\"+\"ef\" == \"abcdef\")\n");
    printf("  unico       : %s\n", hex_unico);
    printf("  incremental : %s\n\n", hex_incremental);
    return 0;
  }
}

// /\/\/\ 
//      /\/\/\ 

int main(void){
  int passou = 0;
  int total  = 4;

  printf(" TESTE SHA-256 \n\n");

  passou += teste_vazio();
  passou += teste_abc();
  passou += teste_multibloco();
  passou += teste_incremental();

  printf("resultado: %d/%d testes passaram\n", passou, total);

  return (passou == total) ? 0 : 1;
}
