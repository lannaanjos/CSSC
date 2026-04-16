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
#define NK_256 8  // 8 x 32 = 256 bits -> 14 rodadas

// Nr -> n° de rodadas  = Nk + 6
#define NR(nk) ((nk)+6) // macro: Nr a partir do Nk

// Key Schedule produz (Nr + 1) subchaves de 128 bits cada.
// Máximo = AES-256 -> 14 + 1 = subchaves -> 15 x 16 = 240 bytes
#define TAM_CHAVE_128 176     // (10 + 1) x 16 = 176
#define TAM_CHAVE_192 208     // (12 + 1) x 16 = 208
#define TAM_CHAVE_256 240     // (14 + 1) x 16 = 240
#define TAM_MAX_CHAVE_EXPANDIDA 240 // max possivel 

// Constantes MixColumns
// x⁸ + x⁴ + x³ + x + 1 = 0x11B
// usa-se 0x1B porque descartamos o bit x⁸
#define GF_POLINOMIO_IRREDUTIVEL 0x1B
// somada (xor) após transform afim enquanto gera a sbox, p nenhum byte mapear a si msm 
#define GF_TRANSFORMACAO_AFIM 0x63

// Constantes do Key Schedule 
// RCON (Round Constant) são constantes usadas na expansão de chave para diferenciar cada rodada 
// são potências de 2 em GF(2⁸) rcon[i] = 2^(i-1)
// como o aes256 usat até 7 rodadas de expansõa, usamos 10 valores para cobrir tudo tranquilamente
static const uint8_t RCON[10] = {
  0x01, 0x02, 0x04, 0x08, 0x10,
  0x20, 0x40, 0x80, 0x1B, 0x36
};

// /\ TABELAS GLOBAIS S-BOX
// cada tabela tem 256 entradas (1/valor de byte)
// sbox[x] -> substituto de x na cifragem
// sbox_inversa[x] -> substituto de x na decifragem
uint8_t sbox[256];
uint8_t sbox_inversa[256];

// /\ STATE 
// o state é matrix 4x4 que representa o bloco sendo processado cada rodada 
// estado[linha][coluna]
typedef uint8_t state_t[4][4];

// /\ ARITIMÉTICA EM GF(2⁸)
uint8_t xtime(uint8_t valor);
uint8_t multiplicacao_gf(uint8_t byte_x, uint8_t byte_y);
uint8_t gf_inverso(uint8_t byte);

// /\ S-BOX
void gerar_sbox(void);

// /\ EXPANSÃO DE CHAVE
// recebe a chave e o nk e preenche o buffer de subkeys
void expansao_chave(const uint8_t *chave, uint8_t subchaves[TAM_MAX_CHAVE_EXPANDIDA], int nk);

// /\ CIFRAGEM
void substituir_bytes(state_t estado);
void embaralhar_linhas(state_t estado);
void misturar_colunas(state_t estado);
void add_chave_rodada(state_t estado, const uint8_t *subkey_round);

// /\ DECIFRAGEM
void sub_bytes_inversos(state_t estado);
void embaralhar_linhas_inverso(state_t estado);
void misturar_colunas_inverso(state_t estado);

// /\ PRINCIPAIS FUNÇÕES DO FLUXO
void cifragem(const uint8_t entrada_original[TAMANHO_BYTES_ENTRADA],
                    const uint8_t subkeys[TAM_MAX_CHAVE_EXPANDIDA],
                    uint8_t cifra[TAMANHO_BYTES_ENTRADA],
                    int nk);

void decifragem(const uint8_t cifra[TAMANHO_BYTES_ENTRADA],
                    const uint8_t subkeys[TAM_MAX_CHAVE_EXPANDIDA],
                    uint8_t entrada_original[TAMANHO_BYTES_ENTRADA],
                    int nk);

// IMPLEMENTANDO
//   o xtime multiplica um byte por dois dentro do gf(2⁸)
//   step by step
//   1. verifica-se se o bit 7 é 1 (antes do shift pq dps ele se perde)
//   2. desloca-se todos os bits p posição esquerda (multiplicar polinomio por x)
//   o resultado pode ter nove bits mas o uint8_t descarta o extra 
//   3. se o bit 7 era 1, o polinomio ultrapasssou o grau 8 e tem q ser reduzido
//   por isso, fazemor XOR com 0x1B, o poli redutor do aes sem o bit x⁸
//
//  EX: 0x57 (0b01010111):
//  bit 7 = 0, ent n precisa reduzir 
//  shift = 0b10101110 = 0xAE (resultado)
//
//  EX: 0xAE (0b10101110):
//  bit 7 = 1, ent precisa reduzir 
//  shift 0b010111100 = 0x5C
//  0x5C XOR 0x1B = 0x47 (resultado)
//

uint8_t xtime(uint8_t valor){
  // isola o bit c a mask x80
  // se resultado != 0, bit 7 era 1 
  uint8_t bit7_eh_um = (valor & 0x80);

  // desloca tudo p esquerda
  uint8_t resultado = (uint8_t)(valor << 1);

  // se bit7 era 1, reduz 
  if (bit7_eh_um) {
    resultado ^= GF_POLINOMIO_IRREDUTIVEL;
  }

  return resultado;
}

// multiplicacao gf: x dois bytes em gf(2⁸)
//
// fazemos multiplicação por partes, inspecionamos o byte_y bit a bit, para cada bit q for 1 
// acumula-se a potência correspondente de byte_x via xtime 

uint8_t multiplicacao_gf(uint8_t byte_x, uint8_t byte_y){
  uint8_t resultado = 0;

  for (int i = 0; i < 8; i++){
    // se o bit menos significativo do byte_y for 1, o termo do byte_x junta no resultado
    if (byte_y & 0x01){
      resultado ^= byte_x;
    }
    // avança byte_x uma potência de x 
    byte_x = xtime(byte_x);

    // consome o bit menos significativo de byte_y
    byte_y >>= 1;
  }

  return resultado;
}

// gf inverso: acha o inverso multiplicador em gf 2 a 8 
//
// o inverso do byte é o valor x tal que:
// multiplicacao_gf(byte,x) == 1 
// 
// tem q testar todos os 255 candidatos
// o byte 0x00 n tem inverso pela definição do corpo finito, por isso retorna 0 p ele
//
// processo é lento, mas como só se usa na geração da s-box vale mais a pena prezar pela
// simplicidade do que pela performance

uint8_t gf_inverso(uint8_t byte){
  if (byte == 0x00) return 0x00;

  for (uint16_t candidato = 0x01; candidato <= 0xFF; candidato++){
    if (multiplicacao_gf(byte, (uint8_t)candidato) == 0x01){
      return (uint8_t)candidato;
    }
  }
  // a ideia é nunca chegar nesse return 
  return 0x00;
}

// gera s-box e s-box inversa 
// p cada byte possivel, o valor da s-box é calculado em 2 passo 
// 1. calcula o inverso multiplicativo em gf 2 a 8 
// 2 aplica transformação afim: cada bit do result é uma combinação xor de alguns bits do inverso
// de acordo com o padrão aes.
// isso é feito com rotações do byte e sucessões de XOR, finalizando com o xor da const x63
//
// a s-box inversa é preenchida simultaneamente, se s-box[x] = y, ent sbox_inversa[y] = x 



static uint8_t rotacao_circular(uint8_t byte, int n){

}



int main(){
  return 0;
}




