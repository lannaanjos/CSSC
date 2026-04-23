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
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0){
    perror("Não foi possível abrir /dev/urandom");
    exit 1;
  }
}

int main(){
  return 0;
}
