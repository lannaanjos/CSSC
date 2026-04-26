#include <stdio.h>

// codidificar texto ou dado binário em string ASCII usando 64 caracteres (a-z min e maiusculo, 0 a 9, +e /)
/*
  PASSO 1:
   pegar o binário de cada carater

  PASSO 2:
   concatenar os bits pra ter 24 bits

  PASSO 3:
   dividir em grupos de 6 bits
   6 porque 2⁶ = 64, cada grupo mapeia p um caracter base64 

  PASSO 4:
   converter cada grupo p um número e dps pra um caracter base64 

  OBS: a entrada precisa ser um multiplo de 3 bytes, qnd n for o caso, é necessário rtealizar o padding
  ex: "Ma"
  M = 01001101
  a = 01100001

  concatena eles, vamos ficar com 16. logo, para deixar com 18 bits, suficiente para dividir em grupos de 6, vamos add mais dois zeros: 010011010110000100
  aí vamos ter 3 grupos ao invés de 4. para cada byte faltante, o resultado final terá '='

*/

int main(){
  return 0;
}
