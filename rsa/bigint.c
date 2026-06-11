// /\/\/\ bigint.c
// implementação da aritmética de inteiros grandes para o RSA
// representação big-endian: digitos[0] é o limb mais significativo

#include <string.h>
#include <stdio.h>
#include "bigint.h"

// /\ utils
// zera
void bigint_zero(BigInt *a){
  memset(a->digitos, 0, sizeof(a->digitos));
}

// init uint32
void bigint_de_u32(BigInt *a, uint32_t val){
  bigint_zero(a);
  a->digitos[BIGINT_LIMBS - 1] = val;
}
int bigint_igual(const BigInt *a, const BigInt *b){
  return memcmp(a->digitos, b->digitos, sizeof(a->digitos)) == 0;
}

// percorre limb mais significativo p menos significativo
int bigint_cmp(const BigInt *a, const BigInt *b){
  int i;
  for (i = 0; i < BIGINT_LIMBS; i++){
    if (a->digitos[i] > b->digitos[i]) return  1;
    if (a->digitos[i] < b->digitos[i]) return -1;
  }
  return 0;
}

// /\ ARITMÉTICA BÁSICA

// percorre do limb menos significativo (digitos[63]) ao mais (digitos[0])
// a soma de dois limbs de 32 bits pode produzir 33 bits
// o bit extra é o carry, passado pro limb seguinte via uint64_t temporário
// retorna 1 se houve overflow (carry saiu dos 2048 bits)
//0 caso contrário
int bigint_add(BigInt *resultado, const BigInt *a, const BigInt *b){
  uint64_t soma;
  uint32_t carry = 0;
  int i;

  for (i = BIGINT_LIMBS - 1; i >= 0; i--){
    soma = (uint64_t)a->digitos[i] + (uint64_t)b->digitos[i] + carry;
    resultado->digitos[i] = (uint32_t)soma;
    carry = (uint32_t)(soma >> 32);
  }

  return (int)carry;
}

// percorre do limb menos significativo ao mais significativo
// se (a->digitos[i] - b->digitos[i] - borrow) for negativo,
// promovemos pra uint64_t e somamos 2^32 (empréstimo do limb seguinte)
// o borrow extraído do bit 32 indica q o empréstimo ocorreu
// assume a >= b: comportamento indefinido caso contrário
int bigint_sub(BigInt *resultado, const BigInt *a, const BigInt *b){
  uint64_t diff;
  uint32_t borrow = 0;
  int i;

  for (i = BIGINT_LIMBS - 1; i >= 0; i--){
    diff = (uint64_t)a->digitos[i] - (uint64_t)b->digitos[i] - borrow;
    resultado->digitos[i] = (uint32_t)diff;
    // se diff < 0, o bit 32 estará setado no uint64_t (complemento de 2)
    borrow = (diff >> 32) & 1;
  }

  return (int)borrow;
}

// /\ MULTIPLICAÇÃO

// resultado = a * b
// para cada limb a[i], multiplica por cada limb b[j]
// o produto parcial acumula na posição correta do resultado
// produto de dois uint32_t cabe exatamente em uint64_t sem perda
void bigint_mul(BigInt *resultado, const BigInt *a, const BigInt *b){
  // acumulador intermediário com o dobro de limbs para evitar overflow
  uint64_t acc[BIGINT_LIMBS * 2];
  uint64_t produto;
  int i, j;

  memset(acc, 0, sizeof(acc));

  //índices big-endian: o limb menos significativo está em [BIGINT_LIMBS-1]
  //para i e j variando de 0 a BIGINT_LIMBS-1, o produto parcial a[i]*b[j]
  //contribui para a posição i+j+1 no acumulador de tamanho duplo

  for (i = BIGINT_LIMBS - 1; i >= 0; i--){
    for (j = BIGINT_LIMBS - 1; j >= 0; j--){
      produto = (uint64_t)a->digitos[i] * (uint64_t)b->digitos[j];
      acc[i + j + 1] += produto;
    }
  }

  // propagação de carries: cada posição pode ter acumulado vários produtos
  for (i = 2 * BIGINT_LIMBS - 1; i > 0; i--){
    acc[i - 1] += acc[i] >> 32;
    acc[i] &= 0xFFFFFFFF;
  }

  // copia os BIGINT_LIMBS limbs menos significativos para o resultado
  // os BIGINT_LIMBS mais significativos são descartados (overflow)
  for (i = 0; i < BIGINT_LIMBS; i++){
    resultado->digitos[i] = (uint32_t)acc[BIGINT_LIMBS + i];
  }
}

// /\ AUXILIARES DE DESLOCAMENTO
// desloca a 1 bit para a esquerda: a <<= 1
//retorna o bit q saiu pelo topo (0 ou 1)
static uint32_t bigint_shl1(BigInt *a){
  uint32_t carry = 0, prox;
  int i;

  for (i = BIGINT_LIMBS - 1; i >= 0; i--){
    prox  = a->digitos[i] >> 31;   // bit q vai ser perdido
    a->digitos[i] = (a->digitos[i] << 1) | carry;
    carry = prox;
  }

  return carry;
}

// desloca a 1 bit para a direita: a >>= 1
static void bigint_shr1(BigInt *a){
  uint32_t carry = 0, prox;
  int i;

  for (i = 0; i < BIGINT_LIMBS; i++){
    prox = a->digitos[i] & 1;           // bit q desce pro próximo limb
    a->digitos[i] = (a->digitos[i] >> 1) | (carry << 31);
    carry = prox;
  }
}

// retorna o número de bits significativos de a (posição do bit mais alto)
static int bigint_nbits(const BigInt *a){
  int i, b;

  for (i = 0; i < BIGINT_LIMBS; i++){
    if (a->digitos[i] != 0){
      for (b = 31; b >= 0; b--){
        if (a->digitos[i] & ((uint32_t)1 << b)){
          return (BIGINT_LIMBS - 1 - i) * 32 + b + 1;
        }
      }
    }
  }

  return 0;
}

// /\ DIVISÃO E MÓDULO

// quociente = a / b
// resto     = a % b
// algoritmo: divisão longa por deslocamento de bits
//   1. desloca b para a esquerda até alinhar com o bit mais alto de a
//   2. testa se a >= b deslocado; se sim, subtrai e marca o bit no quociente
//   3. desloca b de volta um bit por vez até voltar ao valor original
void bigint_divmod(BigInt *quociente, BigInt *resto,
                   const BigInt *a, const BigInt *b){
  BigInt divisor, q;
  int deslocamentos, i;
  int bits_a, bits_b;

  bigint_zero(&q);
  divisor = *b;

  bits_a = bigint_nbits(a);
  bits_b = bigint_nbits(b);

  // resto começa como a; subtraímos o divisor deslocado conforme avançamos
  *resto = *a;

  if (bits_b == 0) return; // divisão por zero: retorna sem fazer nada

  deslocamentos = bits_a - bits_b;

  if (deslocamentos < 0){
    // b > a: quociente = 0, resto = a
    *quociente = q;
    return;
  }

  // alinha divisor com o bit mais alto de a
  for (i = 0; i < deslocamentos; i++){
    bigint_shl1(&divisor);
  }

  // percorre cada posição de bit do quociente
  for (i = deslocamentos; i >= 0; i--){
    if (bigint_cmp(resto, &divisor) >= 0){
      bigint_sub(resto, resto, &divisor);
      // marca o bit i no quociente (big-endian)
      q.digitos[BIGINT_LIMBS - 1 - i / 32] |= (uint32_t)1 << (i % 32);
    }
    bigint_shr1(&divisor);
  }

  *quociente = q;
}

// /\ EXPONENCIAÇÃO MODULAR
// resultado = base^exp mod n
// algoritmo square-and-multiply:
//   percorre os bits de exp do mais significativo ao menos significativo
//   para cada bit: eleva resultado ao quadrado mod n
//   se o bit for 1: multiplica resultado pela base mod n
// reduz 2^2048 multiplicações para apenas ~2048 operações
void bigint_expmod(BigInt *resultado,
                   const BigInt *base, const BigInt *exp, const BigInt *n){
  BigInt r, b, quadrado, produto, q;
  int nbits, i, limb_idx, bit_idx;
  uint32_t bit;

  bigint_de_u32(&r, 1);   // resultado começa em 1
  b = *base;

  // reduz base mod n antes de começar
  bigint_divmod(&q, &b, base, n);

  nbits = bigint_nbits(exp);

  for (i = nbits - 1; i >= 0; i--){
    // extrai o bit i de exp (big-endian)
    limb_idx = BIGINT_LIMBS - 1 - i / 32;
    bit_idx  = i % 32;
    bit = (exp->digitos[limb_idx] >> bit_idx) & 1;

    // quadrado: r = r^2 mod n
    bigint_mul(&quadrado, &r, &r);
    bigint_divmod(&q, &r, &quadrado, n);

    // se bit == 1: r = r * base mod n
    if (bit){
      bigint_mul(&produto, &r, &b);
      bigint_divmod(&q, &r, &produto, n);
    }
  }

  *resultado = r;
}

// EUCLIDES ESTENDIDO

// calcula mdc(a, b) e o coeficiente x tal q a*x ≡ mdc(a,b) (mod b)
// quando mdc(a,b) == 1, x é o inverso modular de a em relação a b
// usado para encontrar d tal q e*d ≡ 1 (mod φ(n))
//
// trabalha inteiramente com valores positivos usando a identidade:
//   se o coeficiente fosse negativo, usa coef + modulo no lugar
void bigint_mdc_estendido(BigInt *mdc_out, BigInt *x, BigInt *y,
                          const BigInt *a, const BigInt *b){
  BigInt r0, r1, s0, s1, t0, t1;
  BigInt q, r, s_tmp, t_tmp, prod, diff;
  BigInt zero, um;

  bigint_de_u32(&zero, 0);
  bigint_de_u32(&um,   1);

  r0 = *a;  bigint_de_u32(&s0, 1);  bigint_de_u32(&t0, 0);
  r1 = *b;  bigint_de_u32(&s1, 0);  bigint_de_u32(&t1, 1);

  while (!bigint_igual(&r1, &zero)){
    // q = r0 / r1, r = r0 % r1
    bigint_divmod(&q, &r, &r0, &r1);

    // s_tmp = s0 - q * s1 (mod b)
    // reduz prod mod b antes de subtrair para manter valores dentro do BigInt
    bigint_mul(&prod, &q, &s1);
    bigint_divmod(&diff, &prod, &prod, b);
    if (bigint_cmp(&s0, &prod) >= 0){
      bigint_sub(&s_tmp, &s0, &prod);
    } else {
      bigint_sub(&diff, &prod, &s0);
      bigint_sub(&s_tmp, b, &diff);
    }

    // t_tmp = t0 - q * t1 (mod b)
    // reutiliza o mesmo q calculado acima (q = r0 / r1)
    bigint_mul(&prod, &q, &t1);
    bigint_divmod(&diff, &prod, &prod, b);
    if (bigint_cmp(&t0, &prod) >= 0){
      bigint_sub(&t_tmp, &t0, &prod);
    } else {
      bigint_sub(&diff, &prod, &t0);
      bigint_sub(&t_tmp, b, &diff);
    }

    r0 = r1;  s0 = s1;  t0 = t1;
    r1 = r;   s1 = s_tmp; t1 = t_tmp;
  }

  *mdc_out = r0;
  *x       = s0;
  *y       = t0;
}

// /\ I/O HEXADECIMAL

// escreve a representação hex de a no buffer
// cada limb de 32 bits vira exatamente 8 caracteres hex
// buf deve ter pelo menos BIGINT_LIMBS * 8 + 1 bytes
void bigint_para_hex(const BigInt *a, char *buf){
  int i;

  for (i = 0; i < BIGINT_LIMBS; i++){
    sprintf(buf + i * 8, "%08x", a->digitos[i]);
  }

  buf[BIGINT_LIMBS * 8] = '\0';
}

// inicializa a partir de uma string hexadecimal sem prefixo 0x
// a string deve ter exatamente BIGINT_LIMBS * 8 caracteres
// retorna 0 em sucesso, -1 se a string for inválida
int bigint_de_hex(BigInt *a, const char *hex){
  int i;
  unsigned int val;

  if (strlen(hex) != BIGINT_LIMBS * 8) return -1;

  for (i = 0; i < BIGINT_LIMBS; i++){
    if (sscanf(hex + i * 8, "%8x", &val) != 1) return -1;
    a->digitos[i] = (uint32_t)val;
  }

  return 0;
}
