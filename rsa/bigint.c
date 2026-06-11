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

//limb mais significativo p menos significativo
int bigint_cmp(const BigInt *a, const BigInt *b){
  int i;
  for (i = 0; i < BIGINT_LIMBS; i++){
    if (a->digitos[i] > b->digitos[i]) return  1;
    if (a->digitos[i] < b->digitos[i]) return -1;
  }
  return 0;
}
