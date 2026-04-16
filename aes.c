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
  return (uint8_t)((byte << n) | (byte >> (8-n)));
}

void gerar_sbox(void){
  for (uint16_t i = 0; i <= 0xFF; i++){
    uint8_t byte = (uint8_t)i;

    // inverso multiplicativo 
    uint8_t inverso = gf_inverso(byte);

    // transf afim
    uint8_t tranformado = inverso
      ^ rotacao_circular(inverso, 1)
      ^ rotacao_circular(inverso, 2)
      ^ rotacao_circular(inverso, 3)
      ^ rotacao_circular(inverso, 4);
    
    // xor final 
    tranformado ^= GF_TRANSFORMACAO_AFIM;
    
    // preenche sbox e sbox inversa simultaneamente
    sbox[byte] = tranformado;
    sbox_inversa[tranformado] = byte;
  }
}

// expansão de chave deriva (Nr+1) subchaves a partir da chave original

// rotaciona os 4 bytes de uma apalvra p esq 
static uint32_t rotaciona_palavra(uint32_t palavra){
  return (palavra << 8) | (palavra >> 24);
}

// aplica sbox nos 4 bytes individuais
static uint32_t subpalavra(uint32_t palavra){
  return ((uint32_t)sbox[(palavra >> 24) & 0xFF] << 24) |
           ((uint32_t)sbox[(palavra >> 16) & 0xFF] << 16) |
           ((uint32_t)sbox[(palavra >>  8) & 0xFF] <<  8) |
           ((uint32_t)sbox[(palavra      ) & 0xFF]      );
}

void expansao_chave(const uint8_t *chave, uint8_t subchaves[TAM_MAX_CHAVE_EXPANDIDA], int nk){
  int nr = NR(nk); // nº rodadas
  int total_palavras = (nr + 1) * 4; // total de palavras de 4 bytes
  
  // buffer subkeys = array de palavras
  uint32_t *w = (uint32_t *)subchaves;

  //copia chave original como as primeiras nk palavras
  for (int i = 0; i < nk; i++) {
    w[i] = ((uint32_t)chave[4*i    ] << 24) |
    ((uint32_t)chave[4*i + 1] << 16) |
    ((uint32_t)chave[4*i + 2] <<  8) |
    ((uint32_t)chave[4*i + 3]      );
  }
  
  // derivas palavras restantes 
  for (int i = nk; i < total_palavras; i++){
    uint32_t temp = w[i-1];

    if (i % nk == 0){
      // a cada nk rotaciona e substitui pela sbox
      // aplica const da rodada rcon
      temp = subpalavra(rotaciona_palavra(temp)) ^ ((uint32_t)RCON[i/nk-1] << 24);
    } else if (nk == NK_256 && i % nk == 4){
      // substituiçao extra na metade 
      temp = subpalavra(temp); 
    }

    // cada palavra nova é a xor da Nk posiçoes atrás com temp
    w[i] = w[i-nk] ^ temp;
  }
}

// cifragem -. cifra um bloco de 16 bytes
// 1. copia texto claro para o estado
// 2. add round key incial (subkey 0)
// 3. nr-1 rodas completas.
// 4 iltima rodada sem mixcolumns.
// 5. copia o state p texto cifrado.
//
void add_chave_rodada(state_t estado, const uint8_t *subkey_round){
  for (int col = 0; col < 4; col++){
    for (int linha = 0; linha < 4; linha++){
      estado[linha][col] ^= subkey_round[col * 4 + linha];
    }
  }
}

void substituir_bytes(state_t estado){
  for (int linha = 0; linha < 4; linha++){
    for(int col = 0; col < 4; col++){
      estado[linha][col] = sbox[estado[linha][col]];
    }
  }
}

void embaralhar_linhas(state_t estado){
  for (int linha = 1; linha < 4; linha++){
    // copiamos a linha atual p um buffer temp
    uint8_t temp[4];

    for (int col = 0; col < 4; col++){
      temp[col] = estado[linha][col];
    }

    for (int col = 0; col < 4; col++){
      estado[linha][col] = temp[(col+linha) % 4];
    }
  }
}

void misturar_colunas(state_t estado){
  for (int col = 0; col < 4; col++){
    uint8_t a = estado[0][col];
    uint8_t b = estado[1][col];
    uint8_t c = estado[2][col];
    uint8_t d = estado[3][col];

    // aplicase matriz fixa aes com xtime.
    estado[0][col] = xtime(a) ^ xtime(b)^b ^ c ^ d;
    estado[1][col] = a ^ xtime(b) ^ xtime(c)^c ^ d;
    estado[2][col] = a ^ b ^ xtime(c) ^ xtime(d)^d;
    estado[3][col] = xtime(a)^a ^ b ^ c ^ xtime(d); 
  }
}

void cifragem(const uint8_t entrada_original[TAMANHO_BYTES_ENTRADA],
              const uint8_t subkeys[TAM_MAX_CHAVE_EXPANDIDA],
              uint8_t cifra[TAMANHO_BYTES_ENTRADA],
              int nk){

  int nr = NR(nk);
  state_t estado;

  // copia o bloco de entrada para a matriz de estado (por coluna)
  for (int col = 0; col < 4; col++){
    for (int linha =0; linha < 4; linha ++){
      estado[linha][col] = entrada_original[col * 4 + linha];
    }
  }

  // addroundkey inicial 
  add_chave_rodada(estado, subkeys);

  //rodas PRINCIPAIS
  for (int rodada = 1; rodada <= nr; rodada++){
    substituir_bytes(estado);
    embaralhar_linhas(estado);

    // n aplica mixcolumns na ultima;.
    if (rodada < nr){
      misturar_colunas(estado);
    }

    // subkey da roddada atual começa c rodada*16.
    add_chave_rodada(estado, subkeys + rodada * 16);
  }

  // copia estado p saida.
  for (int col = 0; col < 4; col++){
    for (int linha = 0; linha < 4; linha++){
      cifra[col * 4 + linha] = estado[linha][col];
    }
  }
}

// decifragem
// ops inversas as da cifragem (ordem reversa)

void sub_bytes_inversos(state_t estado){
  // aplica a sbox inversa em cada byte do estado
  // inverso de substituir_bytes
  for (int linha = 0; linha < 4; linha++){
    for (int col = 0; col < 4; col++){
      estado[linha][col] = sbox_inversa[estado[linha][col]];
    }
  }
}

void embaralhar_linhas_inverso(state_t estado){
  for (int linha = 1; linha < 4; linha++){
    uint8_t temp[4];

    // copy linha p buffer
    for (int col = 0; col < 4; col++){
      temp[col] = estado[linha][col];
    }

    // desloca p direita 
    for (int col = 0; col < 4; col++){
      estado[linha][col] = temp[(col - linha + 4) % 4];
    }
  }
}

void misturar_colunas_inverso(state_t estado){
  // usa matriz inversa fixa
  for (int col = 0; col < 4; col++){
    uint8_t a = estado[0][col];
    uint8_t b = estado[1][col];
    uint8_t c = estado[2][col];
    uint8_t d = estado[3][col];

    // aplica-se matriz inversa
    estado[0][col] = multiplicacao_gf(0x0E, a) 
                   ^ multiplicacao_gf(0x0B, b)
                   ^ multiplicacao_gf(0x0D, c)
                   ^ multiplicacao_gf(0x09, d);
    
    estado[1][col] = multiplicacao_gf(0x09, a)
                   ^ multiplicacao_gf(0x0E, b)
                   ^ multiplicacao_gf(0x0B, c)
                   ^ multiplicacao_gf(0x0D, d);
    
    estado[2][col] = multiplicacao_gf(0x0D, a)
                   ^ multiplicacao_gf(0x09, b)
                   ^ multiplicacao_gf(0x0E, c)
                   ^ multiplicacao_gf(0x0B, d);
    
    estado[3][col] = multiplicacao_gf(0x0B, a)
                   ^ multiplicacao_gf(0x0D, b)
                   ^ multiplicacao_gf(0x09, c)
                   ^ multiplicacao_gf(0x0E, d);
  }
}

void decifragem(const uint8_t cifra[TAMANHO_BYTES_ENTRADA],
                const uint8_t subkeys[TAM_MAX_CHAVE_EXPANDIDA],
                uint8_t entrada_original[TAMANHO_BYTES_ENTRADA],
                int nk){

  int nr = NR(nk);
  state_t estado;

  for(int col = 0; col < 4; col++){
    for (int linha = 0; linha < 4; linha++){
      estado[linha][col] = cifra[col * 4 + linha];
    }
  }

  add_chave_rodada(estado, subkeys + nr * 16);

  for (int rodada = nr-1; rodada >= 1; rodada--){
    sub_bytes_inversos(estado);
    embaralhar_linhas_inverso(estado);
    misturar_colunas_inverso(estado);

    // subkey rodada atual
    add_chave_rodada(estado, subkeys + rodada * 16);
  }

  // ultima rodada
  sub_bytes_inversos(estado);
  embaralhar_linhas_inverso(estado);

  add_chave_rodada(estado, subkeys);

  // copia estado p saida
  for (int col = 0; col < 4; col++){
    for (int linha = 0; linha < 4; linha++){
      entrada_original[col * 4 + linha] = estado[linha][col];
    }
  }
}

//func auxliar p imprimir vetores de bytes em hexadecimal
void imprimir_hex(const char* rotulo, const uint8_t* dados, size_t tamanho){
  printf("%s: ", rotulo);
  for (size_t i = 0; i < tamanho; i++){
    printf("%02X", dados[i]);
  }
  printf("\n");
}

int main(){
  gerar_sbox();

  printf("//\\//\\//\\ TESTE AES 128 //\\//\\//\\ \n");
  
  // vetor de teste oficial do nist para AES-128
  // fonte: NIST AESAVS (aes validation suite)
  //
  // chave de 128 bits
  uint8_t chave_128[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };

  // texto de entrada 16 bytes
  uint8_t texto_entry[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };

  // resultado esperado p este vetor de teste (já é conhecido, tem q dar esse valor)
  uint8_t cifra_esperada[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
  };

  // buffers processamento
  uint8_t subkeys[TAM_MAX_CHAVE_EXPANDIDA];
  uint8_t cifra[16];
  uint8_t decifra[16];

  //// aes steps
  expansao_chave(chave_128, subkeys, NK_128);

  cifragem(texto_entry, subkeys, cifra, NK_128);

  // resultados
  imprimir_hex("Chave:            ", chave_128, 16);
  imprimir_hex("Entrada:          ", texto_entry, 16);
  imprimir_hex("Cifra esperada:   ", cifra_esperada, 16);
  imprimir_hex("Cifra calculada:  ", cifra, 16);

  int cifra_correta = memcmp(cifra, cifra_esperada, 16) == 0;
  if(cifra_correta){
    printf("\nCIFRAGEM CORRETA!\n\n");
  } else {
    printf("\nCRIGRAGEM DEU ERRADO.\n\n");
  }

  // decifragem
  decifragem(cifra, subkeys, decifra, NK_128);
  imprimir_hex("Decifrado:        ", decifra, 16);

  int decifragem_correta = memcmp(decifra, texto_entry, 16) == 0;
  if (decifragem_correta){
    printf("\nDECIFRAGEM CORRETA\n\n");
  } else {
    printf("\nDECIFRAGEM DEU ERRADO.\n");
  }

  return 0;
}




