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
#define TAM_CHAVE_256 240     // (14 + 1) x 16 = 240
#define TAM_MAX_CHAVE_EXPANDIDA 240 // max possivel 

// Constantes MixColumns
// x⁸ + x⁴ + x³ + x + 1 = 0x11B
// usa-se 0x11B porque descartamos o bit x⁸
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
// sbox_inversa[x] -> substituto de x na cifragem
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
void embaralahar_linhas_inverso(state_t estado);
void misturar_colunas_invero(state_t estado);

// /\ PRINCIPAIS FUNÇÕES DO FLUXO
void cifragem(const uint8_t entrada_original[TAMANHO_BYTES_ENTRADA],
                    const uint8_t subkeys[TAM_MAX_CHAVE_EXPANDIDA],
                    uint8_t cifra[TAMANHO_BYTES_ENTRADA],
                    int nk);

void decifragem(const uint8_t cifra[TAMANHO_BYTES_ENTRADA],
                    const uint8_t subkeys[TAM_MAX_CHAVE_EXPANDIDA],
                    uint8_t entrada_original[TAMANHO_BYTES_ENTRADA],
                    int nk);







