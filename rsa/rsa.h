// /\/\/\ rsa.h
// interface pública do RSA
// depende de bigint.h para a aritmética de inteiros grandes

#ifndef RSA_H
#define RSA_H

#include "bigint.h"

// /\ SCTRUCTS 

typedef struct {
  BigInt e; // expoente público (normalmente é 65537)
  BigInt n; // módulo
} ChavePublica;

typedef struct {
  BigInt d; // expoente privado
  BigInt n; // módulo
} ChavePrivada;

// /\ GERAÇÃO DE CHAVES

// gera um par de chaves RSA de 2048 bits
// lê entropia de /dev/urandom para geração dos primos p e q
// retorna 0 em sucesso, -1 em falha
int rsa_gerar_chaves(ChavePublica *pub, ChavePrivada *priv);

// /\ CIFRAÇÃO E DECIFRAÇÃO

// cifra a mensagem m com a chave pública
// resultado = m^e mod n
// m deve ser menor que n
void rsa_cifrar(BigInt *resultado, const BigInt *m, const ChavePublica *pub);

// decifra o ciphertext c com a chave privada
// resultado = c^d mod n
void rsa_decifrar(BigInt *resultado, const BigInt *c, const ChavePrivada *priv);

// /\ IO DE CHAVES

// serializa a chave pública em hex (dois campos de BIGINT_LIMBS*8 chars)
// buf deve ter pelo menos 2 * BIGINT_LIMBS * 8 + 2 bytes (separador + terminador)
void rsa_pub_para_hex(const ChavePublica *pub, char *buf);

// serializa a chave privada em hex
void rsa_priv_para_hex(const ChavePrivada *priv, char *buf);

// desserializa chave pública de hex
// retorna 0 em sucesso, -1 se a string for inválida
int rsa_pub_de_hex(ChavePublica *pub, const char *buf);

// desserializa chave privada de hex
int rsa_priv_de_hex(ChavePrivada *priv, const char *buf);

#endif
