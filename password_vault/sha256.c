// /\/\/\ SHA-256 -> função hash q produz 32 bytes a partir de uma mensgaem de qlq tamanho
// 
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// /\ CONSTANTES
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

// /\ VALORES INICIAIS DO HASH (H0 a H7)//
// primeiras 32 frações binárias das raízes quadradas dos primeiros 8 números primos
//
// eles iniciam o estado interno antes de processar qlq bloco da mensagem.

 static const uint32_t H_iniciais[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// /\ FUNCS AUXILIARES

static uint32_t rotacao_direita(uint32_t x, int n){
  return (x >> n) | (x << (32 - n));
  // "x >> n" pega os bits q vão cair fora 
  // "x << (32-n)" pega os bits q caíram e coloca à esquerda
  // o OR | junta
}

static uint32_t rotacao_esquerda(uint32_t x, int n){
  return (x << n) | (x >> (32 - n));
}

// /\ FUNÇÕES LÓGICAS
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

// /\ STRUCT DE CONTEXTO
// mantém o estado do processamento entre camadas.

typedef struct {
  uint32_t estado[8]; // os 8 registradores de 32 bits (hash em progresso)
  uint32_t contador[2]; // contador de bits processados (dois uint32_t p suportar mensagens de até 2^64 bits)
  uint8_t buffer[64]; // buffer p blocos incompletos
} SHA256_CONTEXTO;

// /\ TRANSFORMAÇÃO SHA-256
// processa um único subbloco de 512 bits atualizando o estado.
// recebe o contexto atual e um bloco de dados e aplica 64 rodadas de operações de mistura.

static void transformacao_sha256(SHA256_CONTEXTO *ctx, const uint8_t bloco[64]){
  uint32_t W[64]; // mensagem expandida
  uint32_t a, b, c, d, e, f, g, h;
  uint32_t T1, T2;
  int i;

  // passo 1: preparação do bloco: 
  // o bloco de 64 bytes é convertido em 16 palavras de 32 bits.
  // byte mais significativo primeiro - big endian.
  
  for(i = 0; i < 16; i++){
    W[i] =  ((uint32_t)bloco[4*i] <<      24) |
            ((uint32_t)bloco[4*i + 1] <<  16) |
            ((uint32_t)bloco[4*i + 2] <<   8) |
            ((uint32_t) bloco[4*i + 3]);
  }

  // passo 2: expansão para as 64 palavras
  // serve p espalhas a influência de cada bit da mensagem por todas as rodadas.

  for (i = 16; i < 64; i++){
    W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
  }

  // passo 3: iniciar vars de trabalho.

  a = ctx->estado[0];
  b = ctx->estado[1];
  c = ctx->estado[2];
  d = ctx->estado[3];
  e = ctx->estado[4];
  f = ctx->estado[5];
  g = ctx->estado[6];
  h = ctx->estado[7];

  // passo 4: 64 rodadas de compressão
  // cada rodada usa uma constante P[i], uma palavra de mensagem expandida W[i] e as funções lógicas.
  // a cada rodada, as vars são rotacionadas e atualizadas.
  // a ideia é ser altamente não-linear

  for (i = 0; i < 64; i++){
    T1 = h + sigma1(e) + Choose(e, f, g) + P[i] + W[i];
    T2 = Sigma0(a) + Majority(a, b, c);

    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }

  // passo 5: atualizar estado do contexto.

  ctx->estado[0] += a;
  ctx->estado[1] += b;
  ctx->estado[2] += c;
  ctx->estado[3] += d;
  ctx->estado[4] += e;
  ctx->estado[5] += f;
  ctx->estado[6] += g;
  ctx->estado[7] += h;
}

// /\ Inicialização do SHA256 
// deve ser chamada antes de começar a processar uma msg.

void sha256_init(SHA256_CONTEXTO *ctx){
  //copia valores inciais p estado
  for (int i = 0; i < 8; i++){
    ctx->estado[i] = H_iniciais[i];
  }

  // zera contador de bits
  ctx->contador[0] = 0;
  ctx->contador[1] = 0;

  // zera buffer (p segurança)
  memset(ctx->buffer, 0, 64);
}

// /\ Atualização SHA256
// processa dados em chunks e pode ser chamada várias vezes com pedaços da msg.

void sha256_atualiza(SHA256_CONTEXTO *ctx, const uint8_t *dados, size_t tam){
  size_t i;
  size_t espaco_buffer;
  uint32_t conta_bytes;

  if (tam == 0) return;

  // contador[0] guarda os bits menos sigs e contados[1] os mais significativos 
  // multiplica tam por 8 p converter byets em bits
  // usa-se uma var temp p evitar overflow.

  conta_bytes = ctx->contador[0] + (tam << 3);

  // se acontecver overflow em contador[0] incrementa cont[1]
  if (conta_bytes < ctx->contador[0]){
    ctx->contador[1]++;
  }

  ctx->contador[0] = conta_bytes;
  ctx->contador[1] += (tam >> 29); // 2^32 bits = 536870912 bytes, ent shift 29 

  // preenchimento do buffer.
  // se houver lixo no buffer, completamos até 64 bytes e então processamos o bloco completo.

  size_t bytes_no_buffer = (ctx->contador[0] >> 3) % 64;
  espaco_buffer = 64 - bytes_no_buffer;
  

  if (tam >= espaco_buffer){
    // copia oq cabe p completar o buffer
    memcpy(ctx->buffer + (64 - espaco_buffer), dados, espaco_buffer);
    
    // processa bloco completo
    transformacao_sha256(ctx, ctx->buffer);

    // processa blocos completos restantes.
    for (i = espaco_buffer; i + 64 <= tam; i+=64){
      transformacao_sha256(ctx, dados + i);
    }

    // reseta buffer
    memset(ctx->buffer, 0, 64);
  } else {
    i = 0;
  }

  // copia resto dos dados p buffer (< q um bloco)
  if (i < tam){
    memcpy(ctx->buffer + (64 - espaco_buffer) + (i - espaco_buffer), dados + i, tam - i);
  }
}

// /\ SHA-256 FINAL 
// finaliza hash, aplica o padding, e gera resultado final.
/*
  Padding:
  1. adiciona um bit '1'
  2. adiciona bits '0' até o comprimento ser multiplo de 512.
  3. adiciona o comprimento original em bits (64 bits, big endian)
*/ 

void sha256_final(SHA256_CONTEXTO *ctx, uint8_t hash[32]){
  uint32_t i;
  uint32_t bits_altos, bits_baixos;
  size_t tam_atual;
  uint8_t padding[64];

  // preparação do padding
  // ele sempre começa com 0x00 (bit 1 seguido de zeros

  memset(padding, 0, sizeof(padding));
  padding[0] = 0x80;

  // calc espaço necessário
  // é necessário q a msg + padding seja multiplo de 521,
  //
  // tam_atual = bytes ja processados % 64;
  // espaço necessario = 56 - tam_atual (se > 0, senão +64)

  tam_atual = (ctx->contador[0] >> 3) % 64;

  if (tam_atual < 56){
    // cabe padding
    sha256_atualiza(ctx, padding, 56 - tam_atual);
  } else {
    sha256_atualiza(ctx, padding, 64 + 56 - tam_atual);
  }

  // add comprimento original
  bits_altos = ctx->contador[1];
  bits_baixos = ctx->contador[0];
    
  padding[0] = (bits_altos >> 24) & 0xFF;
  padding[1] = (bits_altos >> 16) & 0xFF;
  padding[2] = (bits_altos >> 8) & 0xFF;
  padding[3] = bits_altos & 0xFF;
  padding[4] = (bits_baixos >> 24) & 0xFF;
  padding[5] = (bits_baixos >> 16) & 0xFF;
  padding[6] = (bits_baixos >> 8) & 0xFF;
  padding[7] = bits_baixos & 0xFF;

  sha256_atualiza(ctx, padding, 8);

  // extração do hash final
  // state final tem 8 palavras de 32 bits, convertemos cada uma p big-endian

  for (i = 0; i < 8; i++){
    hash[4*i] =     (ctx->estado[i] >> 24) & 0xFF;
    hash[4*i + 1] = (ctx->estado[i] >> 16) & 0xFF;
    hash[4*i + 2] = (ctx->estado[i] >> 8) & 0xFF;
    hash[4*i + 3] = (ctx->estado[i]) & 0xFF;
  }
}

// /\ FUNC AUXILIAR 
// func q faz init, update e final de uma vez.

void sha256(const uint8_t *dados, size_t tam, uint8_t hash[32]){
  SHA256_CONTEXTO ctx;
  sha256_init(&ctx);
  sha256_atualiza(&ctx, dados, tam);
  sha256_final(&ctx, hash);
}
