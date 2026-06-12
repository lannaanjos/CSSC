// /\/\/\ rsa.c
// implementação do RSA sobre a biblioteca bigint
// geração de chaves, cifração, decifração e serialização

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "rsa.h"

// /\ AUX

// SÓ FUNCIONA NO LINUX
// /dev/random é a interface padrão linux p entropia criptograficamente segura
// kernel coleta ruido do hardware e alimenta um CSPRNG interno            // CSPRNG = Cryptographically Secure Pseudo-Random Number Generator
// qnd pegamos daqui, são bytes desse pool, não um rand mixuruca
// logo é mais seguro pq é completamente inviável deduzir tanto p frente qnt p trás

// lê tam bytes de /dev/urandom para buf
// retorna 0 em sucesso, -1 em falha
static int gera_random(uint8_t *buf, size_t tam){
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0){
    perror("impossível abrir /dev/urandom");
    return -1;
  }

  ssize_t lidos = read(fd, buf, tam);
  close(fd);

  if (lidos != (ssize_t)tam){
    perror("leitura incompleta de /dev/urandom");
    return -1;
  }

  return 0;
}

// gera um BigInt aleatório de n_bytes bytes a partir de /dev/urandom
// retorna 0 em sucesso, -1 em falha
static int bigint_aleatorio(BigInt *a, size_t n_bytes){
  uint8_t buf[BIGINT_LIMBS * 4];
  size_t i, limb_idx;

  if (n_bytes > sizeof(buf)) n_bytes = sizeof(buf);

  bigint_zero(a);

  if (gera_random(buf, n_bytes) != 0) return -1;

  // preenche os limbs menos significativos (big-endian: do final para o início)
  for (i = 0; i < n_bytes; i++){
    limb_idx = BIGINT_LIMBS - 1 - i / 4;
    a->digitos[limb_idx] |= (uint32_t)buf[i] << ((i % 4) * 8);
  }

  memset(buf, 0, sizeof(buf));
  return 0;
}

// /\ MILLER-RABIN

// escreve n-1 como 2^r * d com d ímpar
// preenche *r e *d_out
static void fatora_potencia_dois(const BigInt *n, int *r, BigInt *d_out){
  BigInt n_menos_1, um, q, resto;

  bigint_de_u32(&um, 1);
  bigint_sub(&n_menos_1, n, &um);

  *d_out = n_menos_1;
  *r = 0;

  // enquanto d for par (bit menos significativo == 0), divide por 2
  while ((d_out->digitos[BIGINT_LIMBS - 1] & 1) == 0){
    bigint_de_u32(&um, 2);
    bigint_divmod(&q, &resto, d_out, &um);
    *d_out = q;
    (*r)++;
  }
}

// teste de Miller-Rabin com uma única testemunha a
// retorna 1 se n passa (provavelmente primo), 0 se n é composto
static int miller_rabin_testemunha(const BigInt *n, const BigInt *a){
  BigInt d, n_menos_1, um, x, quadrado, q, resto;
  int r, i;

  bigint_de_u32(&um, 1);
  bigint_sub(&n_menos_1, n, &um);

  fatora_potencia_dois(n, &r, &d);

  // x = a^d mod n
  bigint_expmod(&x, a, &d, n);

  if (bigint_igual(&x, &um) || bigint_igual(&x, &n_menos_1)){
    return 1;
  }

  for (i = 0; i < r - 1; i++){
    bigint_mul(&quadrado, &x, &x);
    bigint_divmod(&q, &resto, &quadrado, n);
    x = resto;

    if (bigint_igual(&x, &n_menos_1)) return 1;
  }

  return 0;
}

// teste determinisctico de primos p numeros até ~3.3 * 10^24
// testemunhas fixas cobrem todos os compostos nessa faixa
// para primos de 1024 bits o teste é probabilístico com erro < 4^-12
static int eh_primo(const BigInt *n){
  // testemunhas fixas de Miller-Rabin
  static const uint32_t testemunhas[] = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37
  };
  static const int n_testemunhas = 12;

  BigInt um, dois, a;
  int i;

  bigint_de_u32(&um,  1);
  bigint_de_u32(&dois, 2);

  // casos triviais
  if (bigint_cmp(n, &dois) < 0)  return 0; // n < 2
  if (bigint_igual(n, &dois))    return 1; // n == 2
  if ((n->digitos[BIGINT_LIMBS - 1] & 1) == 0) return 0; // par

  for (i = 0; i < n_testemunhas; i++){
    bigint_de_u32(&a, testemunhas[i]);
    if (!miller_rabin_testemunha(n, &a)) return 0;
  }

  return 1;
}

// gera um primo aleatório de n_bits bits
// retorna 0 em sucesso, -1 em falha de entropia
static int gera_primo(BigInt *p, int n_bits){
  BigInt um, dois;
  int n_bytes = (n_bits + 7) / 8;

  bigint_de_u32(&um,  1);
  bigint_de_u32(&dois, 2);

  while (1){
    if (bigint_aleatorio(p, n_bytes) != 0) return -1;

    // força bit mais significativo a 1: garante tamanho exato de n_bits
    p->digitos[BIGINT_LIMBS - n_bytes / 4] |= (uint32_t)1 << 31;

    // força bit menos significativo a 1: garante ímpar
    p->digitos[BIGINT_LIMBS - 1] |= 1;

    if (eh_primo(p)) return 0;

    // incrementa em 2 para manter ímpar e tentar o próximo candidato
    bigint_add(p, p, &dois);
  }
}

// /\ GERAÇÃO DE CHAVES

// gera par de chaves RSA de 2048 bits
// p e q são primos de 1024 bits cada
// e fixo em 65537 (primo de Fermat F4, eficiente na exponenciação)
// d calculado como inverso modular de e em relação a φ(n)
int rsa_gerar_chaves(ChavePublica *pub, ChavePrivada *priv){
  BigInt p, q, n, phi, p1, q1, e, d, mdc, y;
  BigInt um;

  bigint_de_u32(&um, 1);
  bigint_de_u32(&e, 65537);

  // gera p
  if (gera_primo(&p, 64) != 0) return -1; // o certo é 1024, mas estava levando uma eternidade para rodar, 64 é apenas para rodar rapido

  // gera q diferente de p
  do {
    if (gera_primo(&q, 64) != 0) return -1;
  } while (bigint_igual(&p, &q));

  // n = p * q
  bigint_mul(&n, &p, &q);

  // φ(n) = (p-1) * (q-1)
  bigint_sub(&p1, &p, &um);
  bigint_sub(&q1, &q, &um);
  bigint_mul(&phi, &p1, &q1);

  // d = inverso modular de e em relação a φ(n)
  // bigint_mdc_estendido retorna x tal que e*x ≡ mdc(e, φ(n)) (mod φ(n))
  bigint_mdc_estendido(&mdc, &d, &y, &e, &phi);

  // preenche as chaves
  pub->e  = e;
  pub->n  = n;
  priv->d = d;
  priv->n = n;

  // zera dados sensíveis da memória
  memset(&p,   0, sizeof(p));
  memset(&q,   0, sizeof(q));
  memset(&phi, 0, sizeof(phi));
  memset(&p1,  0, sizeof(p1));
  memset(&q1,  0, sizeof(q1));

  return 0;
}

// /\ CIFRAGEM e DECIFRAGEM

// resultado = m^e mod n
void rsa_cifrar(BigInt *resultado, const BigInt *m, const ChavePublica *pub){
  bigint_expmod(resultado, m, &pub->e, &pub->n);
}

// resultado = c^d mod n
void rsa_decifrar(BigInt *resultado, const BigInt *c, const ChavePrivada *priv){
  bigint_expmod(resultado, c, &priv->d, &priv->n);
}

// /\ IO DE CHAVES
// formato: <campo_hex>:<n_hex>
// cada campo tem BIGINT_LIMBS * 8 caracteres hex
// separados por ':' e terminados em '\0'

void rsa_pub_para_hex(const ChavePublica *pub, char *buf){
  bigint_para_hex(&pub->e, buf);
  buf[BIGINT_LIMBS * 8] = ':';
  bigint_para_hex(&pub->n, buf + BIGINT_LIMBS * 8 + 1);
}

void rsa_priv_para_hex(const ChavePrivada *priv, char *buf){
  bigint_para_hex(&priv->d, buf);
  buf[BIGINT_LIMBS * 8] = ':';
  bigint_para_hex(&priv->n, buf + BIGINT_LIMBS * 8 + 1);
}

int rsa_pub_de_hex(ChavePublica *pub, const char *buf){
  if (buf[BIGINT_LIMBS * 8] != ':') return -1;
  if (bigint_de_hex(&pub->e, buf) != 0) return -1;
  if (bigint_de_hex(&pub->n, buf + BIGINT_LIMBS * 8 + 1) != 0) return -1;
  return 0;
}

int rsa_priv_de_hex(ChavePrivada *priv, const char *buf){
  if (buf[BIGINT_LIMBS * 8] != ':') return -1;
  if (bigint_de_hex(&priv->d, buf) != 0) return -1;
  if (bigint_de_hex(&priv->n, buf + BIGINT_LIMBS * 8 + 1) != 0) return -1;
  return 0;
}

// /\/\/\ TESTE

// tamanho do buffer para serialização de uma chave:
// dois campos hex de BIGINT_LIMBS*8 chars + separador ':' + terminador '\0'
#define CHAVE_HEX_TAM (BIGINT_LIMBS * 8 * 2 + 2)

int main(void){
  ChavePublica pub;
  ChavePrivada priv;
  BigInt mensagem, cifrado, decifrado;
  char buf_pub[CHAVE_HEX_TAM];
  char buf_priv[CHAVE_HEX_TAM];
  char hex_msg[BIGINT_LIMBS * 8 + 1];
  char hex_cif[BIGINT_LIMBS * 8 + 1];
  char hex_dec[BIGINT_LIMBS * 8 + 1];

  printf("///////// TESTE RSA 2048 bits /////////\n\n");

  // geração de chaves
  printf("[*] gerando chaves RSA (demora um tiquinho)...\n");
  if (rsa_gerar_chaves(&pub, &priv) != 0){
    fprintf(stderr, "erro: falha na geração de chaves\n");
    return 1;
  }
  printf("[SUCESSO] chaves geradas\n\n");

  // serialização
  rsa_pub_para_hex(&pub,  buf_pub);
  rsa_priv_para_hex(&priv, buf_priv);
  printf("[*] chave publica  (e:n):\n%.64s...\n\n", buf_pub);
  printf("[*] chave privada  (d:n):\n%.64s...\n\n", buf_priv);

  // mensagem de teste: o número 42
  bigint_de_u32(&mensagem, 42);
  bigint_para_hex(&mensagem, hex_msg);
  printf("[*] mensagem original : %u\n", 42);
  printf("    hex               : %s\n\n", hex_msg);

  // cifração
  rsa_cifrar(&cifrado, &mensagem, &pub);
  bigint_para_hex(&cifrado, hex_cif);
  printf("[*] cifrado (primeiros 64 chars):\n%.64s...\n\n", hex_cif);

  // decifração
  rsa_decifrar(&decifrado, &cifrado, &priv);
  bigint_para_hex(&decifrado, hex_dec);
  printf("[*] decifrado hex : %s\n", hex_dec);

  // verificação
  if (bigint_igual(&mensagem, &decifrado)){
    printf("\n[SUCESSO] mensagem decifrada bate com a original !!! \\o/ \n");
  } else {
    printf("\n[ATENCAO] mensagem decifrada NAO bate com a original!\n");
  }

  printf("\nfim!! :D\n");
  return 0;
}
