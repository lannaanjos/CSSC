// SHA-256 -> função hash q produz 32 bytes a partir de uma mensgaem de qlq tamanho
// 
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// CONSTANTES
// primeiras 32 frações binárias das raízes cúbicas do primeiros 64 nros primos.

static const uint32_t P[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// VALORES INICIAIS DO HASH (H0 a H7)//
// primeiras 32 frações binárias das raízes quadradas dos primeiros 8 números primos
//
// eles iniciam o estado interno antes de processar qlq bloco da mensagem.

 static const uint32_t H_iniciais[8]{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// FUNCS AUXILIARES

static uint32_t rotacao_direita(uint32_t x, int n){
  return (x >> n) | (x << (32 - n));
  // "x >> n" pega os bits q vão cair fora 
  // "x << (32-n)" pega os bits q caíram e coloca à esquerda
  // o OR | junta
}

static uint32_t rotacao_esquerda(uint32_t x, int n){
  return (x << n) | (x >> (32 - n));
}

// FUNÇÕES LÓGICAS
// usdas em cada rodada p misturar os bits
//
// Choose: escolhe bits de x ou y baseado em e. Se x for 1, escolhe y. Se x for 0, escolhe z.
// Majority: maioria entre x, y, z. Retorna 1 se pelo menos dois dos três bits forem 1.
// Sigma0: rotações + shift usadas na expansão/compressão da mensagem. Mistura o bit com seus vizinhos rotacionados.
// Sigma1: rotações + shift usadas na atualização do estado. Similar a Sigma0 mas com rotações diferentes.
// sigma0: rotações + shift (expansão).
// sigma1: rotações + shift (expansão).

static uint32_t Choose(uint32_t x, uint32_t y, uint32_t z){
  return (x & y) ^ (~x & z);
}

static uint32_t Majority(uint32_t a, uint32_t b, uint32_t c){
  return (a & b) ^ (a & c) ^ (b & c);
}

static uint32_t Sigma0(uint32_t x){
  return rotacao_direita(x, 2) ^ rotacao_direita(x, 13) ^ rotacao_direita(x, 22);
}

static uint32_t Sigma1(uint32_t x){
  return rotacao_direita(x, 6) ^ rotacao_direita(x, 11) ^ rotacao_direita(x, 25);
}

static uint32_t sigma0(uint32_t x){
  return rotacao_direita(x, 7) ^ rotacao_direita(x, 18) ^ (x >> 3);
}

static uint32_t sigma1(uint32_t x){
  return rotacao_direita(x, 17) ^ rotacao_direita(x, 19) ^ (x >> 10);
}

// STRUCT DE CONTEXTO
// mantém o estado do processamento entre camadas.

typedef struct {
  uint32_t estado[8]; // os 8 registradores de 32 bits (hash em progresso)
  uint32_t contador[2]; // contador de bits processados (dois uint32_t p suportar mensagens de até 2^64 bits)
  uint32_t buffer[64]; // buffer p blocos incompletos
} SHA256_CONTEXTO;





