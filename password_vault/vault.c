#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// só funcionam no linux, tem q trocar p usar no windows
#include <unistd.h> // POSIX
#include <fcntl.h> // p abrir dev/urandom

#include "aes.h"
#include "pbkdf2.h"

// /\ CONSTANTES
#define SALT_TAMANHO 16
#define IV_TAMANHO 16
#define BLOCO_ENTRADA_TAM 16
#define ITER_PBKDF2 100000
#define CHAVE_TAMANHO 32

// /\ FUNÇÕES AUXILIARES
void gera_random(uint8_t *buffer, size_t tam){
  int fd = open("/dev/urandom", O_RDONLY); // file descriptor
  if (fd < 0){
    perror("Não foi possível abrir /dev/urandom");
    exit 1;
  }

  ssizte_t bytes_lidos = read(fd, buffer tam);

  if (bytes_lidos != (ssizte_t)tam){
    // n leu a qnt pedida
    perror("Não foi possível ler /dev/urandom");
    close(fd);
    exit(1);
  }

  close(fd);
}

void xor_bytes(uint8_t *destino, const uint8_t *origem, size_t tam){
  for (size_t i = 0; i < tam; i++){
    destino[i] ^= origem[i];
  }
}

// /\ ADD PADDING
void padding_pkcs7(uint8_t *dados, size_t tam_original, size_t *tam_padded){
  // calcula qnts bytes faltam p dar um bloc.
  size_t resto = tam_original % BLOCO_ENTRADA_TAM;
  size_t bytes_faltando = BLOCO_ENTRADA_TAM - resto;

  // se tam já é multiplo de 16 add um bloco inteiro de padding 
  if (resto == 0){
    bytes_faltando = BLOCO_ENTRADA_TAM;
  }

  // add padding
  for (size_t i = 0; i < bytes_faltando; i++){
    dados[tam_original + i] = (uint8_t)bytes_faltando;
  }

  //upt tam total dps do padding
  *tam_padded = tam_original + bytes_faltando;
}

// /\ TIRA PADDING
int unpadding_pkcs7(uint8_t *dados, size_t *tam){
  // tam n pd ser 0 nem multiplo de 16
  if (*tam == 0 || *tam % BLOCO_ENTRADA_TAM != 0){
    return -1;
  }

  // ultimo bytes mostra qnt de padding q tem
  // se ultimo = 0x05, tem 5 bytes de padding por exemplo
  uint8_t val_padding = dados[*tam - 1];

  // verificacao: deve estar entre 1 e 16
  if (val_padding == 0 || val_padding > BLOCO_ENTRADA_TAM){
    return -1;
  }

  // verifica se os valores de padding são tds iguais
  for (size_t i = *tam - val_padding; i < *tam; i++){
    if (dados[i] != val_padding){
      return -1;
    }
  }

  // tira padding
  *tam -= val_padding;

  return 0;

}

// /\ CBC 
void cifra_cbc(const uint8_t *entry, size_t entry_size,
               uint8_t *saida,
               const uint8_t *iv,
               const uint8_t *subkeys){

  // conta blocos 16 bytes
  size_t n_blocos = entry_size / BLOCO_ENTRADA_TAM;

  // buffer p bloco atual do processamento
  uint8_t bloco_a_cifrar[BLOCO_ENTRADA_TAM];

  // buffer bloco anterior
  uint8_t bloco_prev[BLOCO_ENTRADA_TAM];

  // bloco anterior recebe iv 
  memcpy(bloco_prev, iv, BLOCO_ENTRADA_TAM);

  //processamento dos blocos
  for (size_t i = 0; i < n_blocos; i++){ // i é cada um dos blocos
    // copia bloco atual da entrada 
    memcpy(bloco_a_cifrar, entry + i, * BLOCO_ENTRADA_TAM, BLOCO_ENTRADA_TAM);

    // xor com bloco prev cifrado 
    xor_bytes(bloco_a_cifrar, bloco_prev, BLOCO_ENTRADA_TAM);

    // cifragem do resultado (aes)
    cifrar_bloco(bloco_a_cifrar, bloco_prev, subkeys);

    // salva no buffer output
    memcpy(saida + i * BLOCO_ENTRADA_TAM, bloco_prev, BLOCO_ENTRADA_TAM);

  }
}

int main(){
  return 0;
}
