// /\/\/\ authenticator.c
// verifica autenticidade de arquivos via sha256
//
// uso:
//   ./authenticator gerar    <arquivo>
//   ./authenticator verificar <arquivo> <hash>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sha256.h"

// /\ CONSTANTES

#define CHUNK_TAM 4096

// /\ FUNÇÕES AUXILIARES

// lê o arquivo em chunks e produz o hash sha256
// evita carregar o arquivo inteiro em memória
static int hash_arquivo(const char *path, uint8_t hash[32]){
  FILE *f = fopen(path, "rb");
  if (!f){
    perror("impossível abrir arquivo");
    return -1;
  }

  SHA256_CONTEXTO ctx;
  sha256_init(&ctx);

  uint8_t buffer[CHUNK_TAM];
  size_t lidos;

  while ((lidos = fread(buffer, 1, CHUNK_TAM, f)) > 0){
    sha256_atualiza(&ctx, buffer, lidos);
  }

  if (ferror(f)){
    perror("erro ao ler arquivo");
    fclose(f);
    return -1;
  }

  fclose(f);
  sha256_final(&ctx, hash);
  return 0;
}

// converte string hex de 64 chars para 32 bytes
// retorna 0 em sucesso, -1 se a string for inválida
static int hex_para_bytes(const char *hex, uint8_t bytes[32]){
  if (strlen(hex) != 64){
    return -1;
  }

  for (int i = 0; i < 32; i++){
    unsigned int val;
    if (sscanf(hex + 2 * i, "%02x", &val) != 1){
      return -1;
    }
    bytes[i] = (uint8_t)val;
  }

  return 0;
}

// /\/\/\ MODOS DE OPERAÇÃO

// gera e imprime o hash sha256 de um arquivo
static void gerar(const char *path){
  uint8_t hash[32];

  if (hash_arquivo(path, hash) != 0){
    exit(1);
  }

  printf("sha256(%s):\n", path);
  for (int i = 0; i < 32; i++){
    printf("%02x", hash[i]);
  }
  printf("\n");
}

// verifica se o arquivo bate com o hash fornecido
static void verificar(const char *path, const char *hash_str){
  uint8_t hash_calculado[32];
  uint8_t hash_fornecido[32];

  if (hash_arquivo(path, hash_calculado) != 0){
    exit(1);
  }

  if (hex_para_bytes(hash_str, hash_fornecido) != 0){
    fprintf(stderr, "erro: hash inválido (deve ter 64 caracteres hexadecimais)\n");
    exit(1);
  }

  if (memcmp(hash_calculado, hash_fornecido, 32) == 0){
    printf("AUTENTICO\n");
    printf("  arquivo : %s\n", path);
    printf("  hash    : %s\n", hash_str);
  } else {
    printf("INVALIDO\n");
    printf("  arquivo         : %s\n", path);
    printf("  hash fornecido  : %s\n", hash_str);
    printf("  hash calculado  : ");
    for (int i = 0; i < 32; i++) printf("%02x", hash_calculado[i]);
    printf("\n");
  }
}

// /\/\/\ ENTRY POINT

// argv[0] = programa
// argv[1] = comando (gerar | verificar)
// argv[2] = arquivo
// argv[3] = hash (apenas no modo verificar)
int main(int argc, char *argv[]){
  if (argc < 2){
    printf("uso:\n");
    printf("  %s gerar    <arquivo>\n", argv[0]);
    printf("  %s verificar <arquivo> <hash>\n", argv[0]);
    return 1;
  }

  if (strcmp(argv[1], "gerar") == 0){
    if (argc < 3){
      fprintf(stderr, "erro: indique o arquivo\n");
      return 1;
    }
    gerar(argv[2]);

  } else if (strcmp(argv[1], "verificar") == 0){
    if (argc < 4){
      fprintf(stderr, "erro: indique o arquivo e o hash\n");
      return 1;
    }
    verificar(argv[2], argv[3]);

  } else {
    fprintf(stderr, "erro: comando desconhecido '%s'\n", argv[1]);
    return 1;
  }

  return 0;
}