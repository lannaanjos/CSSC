#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

const char CARACTERES_BASE64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* string_p_base64(const char* input){
  int input_tam = strlen(input);

  // calc tamanho da saída
  int output_tam = ((input_tam + 2) / 3) * 4;
  char *output = malloc(output_tam+1);

  int i = 0, j = 0;

  // processa em blocos de 3 bytes
  // base64 pega 3bytes (24 bits) e transforma em 4 caracteres de 6 bits cada
  // aqui pegamos exatamente 3 bytes por opr.
  while (i < input_tam) {
    unsigned char byte1 = input[i++];
    unsigned char byte2 = (i < input_tam) ? input[i++] : 0; // padding
    unsigned char byte3 = (i < input_tam) ? input[i++] : 0; // padding
    
    // concat
    // u int tem 32 bits enquanto u char tem 8
    // aqui separamos os bytes 0, 1, 2 e 3 
    // n existe o operador de concatenção, então precisamos usar o shift à esquerda para mover os bits dentro dos 24 bits
    // com byte1 ocupando os 8 mais à esquerda, byte2 no meio e byte3 ao final à direita
    // após isso, somamos eles. como n tem sobreposição, pois corrigimos com o shift, a soma é equivalente a concatenar
    unsigned int concat_24bits = (byte1 << 16) | (byte2 << 8) | byte3;

    // separação em grupos de 6 bits
    // precisamos fazer shift para a direita para pegar os grupos e fazer AND com uma mascara que tenha 6 bits = 1 e resto = 0
    // 0x3F = 00000000 00000000 00000000 00111111
    // joga tudo pro final (direita) e faz AND com máscara para capturar somente o que precisa
    unsigned char grupo1 = (concat_24bits >> 18) & 0x3F;
    unsigned char grupo2 = (concat_24bits >> 12) & 0x3F;
    unsigned char grupo3 = (concat_24bits >> 6) & 0x3F;     // n to alterando a var de concatenção
    unsigned char grupo4 = concat_24bits & 0x3F;

    output[j++] = CARACTERES_BASE64[grupo1];
    output[j++] = CARACTERES_BASE64[grupo2];
    output[j++] = CARACTERES_BASE64[grupo3];
    output[j++] = CARACTERES_BASE64[grupo4];

  }

  output[j] = '\0';

  return output;
}


int main(){
  int i = 1;
  while(i > 0){
    char frase[256];
    printf("Insira um texto qualquer para transformar em base64: ");
    scanf("%s", frase);

    char *codificado = string_p_base64(frase);

    printf("\nString codificada: %s", codificado);
    printf("\n\nInsira 0 para sair ou 1 para tentar de novo: ");
    scanf("%d", &i);
    printf("\n");
  }

  return 0;
}
