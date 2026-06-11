// /\/\/\ bigint.h
// aritmética de inteiros grandes para uso no RSA
// representação: array de uint32_t em big-endian
//   digitos[0] = limb mais significativo
//   digitos[BIGINT_LIMBS-1] = limb menos significativo
// tamanho fixo: 64 limbs de 32 bits = 2048 bits

#ifndef BIGINT_H
#define BIGINT_H

#include <stdint.h>
#include <stddef.h>

// /\ CONSTANTES
#define BIGINT_LIMBS 64

// /\ ESTRUTURA
typedef struct {
  uint32_t digitos[BIGINT_LIMBS];
} BigInt;

// /\ INICIALIZAÇÃO E UTILITÁRIOS

// zera todos os limbs
void bigint_zero(BigInt *a);

// limb é cada pedaço de um numero grande
// o big int n cabe num tipo nativo do C
// no caso aqui, 64 pedaços de 32 bits cada

// inicializa a partir de um uint32_t
void bigint_de_u32(BigInt *a, uint32_t val);

// retorna 1 se a == b, 0 caso contrário
int bigint_igual(const BigInt *a, const BigInt *b);

// retorna  1 se a > b
// retorna  0 se a == b
// retorna -1 se a < b
int bigint_cmp(const BigInt *a, const BigInt *b);

// /\ ARITMÉTICA BÁSICA

// resultado = a + b
// retorna 1 se houve overflow (carry fora dos 2048 bits), 0 caso contrário
int bigint_add(BigInt *resultado, const BigInt *a, const BigInt *b);

// resultado = a - b
// assume a >= b (comportamento indefinido caso contrário)
// retorna 1 se houve underflow (borrow), 0 caso contrário
int bigint_sub(BigInt *resultado, const BigInt *a, const BigInt *b);

// /\ MULTIPLICAÇÃO

// resultado = a * b
// atenção: pode transbordar os 2048 bits silenciosamente
// para uso no RSA, os operandos devem ter no máximo 1024 bits cada
void bigint_mul(BigInt *resultado, const BigInt *a, const BigInt *b);

// /\ DIVISÃO E MÓDULO

// quociente = a / b
// resto     = a % b
// comportamento indefinido se b == 0
void bigint_divmod(BigInt *quociente, BigInt *resto,
                   const BigInt *a, const BigInt *b);

// /\ EXPONENCIAÇÃO MODULAR

// resultado = base^exp mod n
// coração do RSA, usado na cifragem quanto na decifragem 
void bigint_expmod(BigInt *resultado,
                   const BigInt *base, const BigInt *exp, const BigInt *n);

// /\ ALGORITMO DE EUCLIDES ESTENDIDO

// calcula mdc(a, b) e os coeficientes x, y tais que:
//   a*x + b*y = mdc(a, b)
// usado para encontrar o expoente privado d no RSA
void bigint_mdc_estendido(BigInt *mdc, BigInt *x, BigInt *y,
                          const BigInt *a, const BigInt *b);

// /\ IO HEXADEC
// escreve a representação hex de a no buffer (sem prefixo 0x)
// buf deve ter pelo menos BIGINT_LIMBS * 8 + 1 bytes
void bigint_para_hex(const BigInt *a, char *buf);

// inicializa a partir de uma string hexadecimal (sem prefixo 0x)
// retorna 0 em sucesso, -1 se a string for inválida
int bigint_de_hex(BigInt *a, const char *hex);

#endif
