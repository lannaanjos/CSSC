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
    exit(1);
  }

  ssize_t bytes_lidos = read(fd, buffer, tam);

  if (bytes_lidos != (ssize_t)tam){
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
    memcpy(bloco_a_cifrar, entry + i * BLOCO_ENTRADA_TAM, BLOCO_ENTRADA_TAM);

    // xor com bloco prev cifrado 
    xor_bytes(bloco_a_cifrar, bloco_prev, BLOCO_ENTRADA_TAM);

    // cifragem do resultado (aes)
    cifrar_bloco(bloco_a_cifrar, bloco_prev, subkeys);

    // salva no buffer output
    memcpy(saida + i * BLOCO_ENTRADA_TAM, bloco_prev, BLOCO_ENTRADA_TAM);

  }
}

void decifra_cbc(const uint8_t *entry, size_t entry_size,
                 uint8_t *saida,
                 const uint8_t *iv,
                 const uint8_t *subkeys){

  size_t n_blocos = entry_size / BLOCO_ENTRADA_TAM;

  uint8_t bloco_decifrado[BLOCO_ENTRADA_TAM];
  uint8_t bloco_prev[BLOCO_ENTRADA_TAM];

  // init iv 
  memcpy(bloco_prev, iv, BLOCO_ENTRADA_TAM);

  for (size_t i = 0; i < n_blocos; i++){
    decifrar_bloco(entry + i * BLOCO_ENTRADA_TAM, bloco_decifrado, subkeys);
    xor_bytes(bloco_decifrado, bloco_prev, BLOCO_ENTRADA_TAM);
    // salv resultado
    memcpy(saida + i * BLOCO_ENTRADA_TAM, bloco_decifrado, BLOCO_ENTRADA_TAM);

    // upt bloco prev
    memcpy(bloco_prev, entry + i * BLOCO_ENTRADA_TAM, BLOCO_ENTRADA_TAM);
  }  
}

void cifragem_arquivo(const char *entry_path){
  FILE *entry = fopen(entry_path, "rb");
  if (!entry){
    perror("Impossível abrir aquivo.\n");
    exit(1);
  }

  char saida_path[512];

  snprintf(saida_path, sizeof(saida_path), "%s.cifrado", entry_path);

  FILE *saida = fopen(saida_path, "wb");
    if (!saida){
      perror("Imporssível abrir.\n");
      fclose(entry);
      exit(1);
    }
  

  uint8_t salt[SALT_TAMANHO];
  uint8_t iv[IV_TAMANHO];

  gera_random(salt, SALT_TAMANHO);
  gera_random(iv, IV_TAMANHO);

  // pede senha
  char user_senha[256];
  printf("Insira a senha do arquivo: ");
  if(!fgets(user_senha, sizeof(user_senha), stdin)){
    fprintf(stderr, "Não foi possível ler a senha");
    exit(1);
  }

  user_senha[strcspn(user_senha, "\n")] = '\0';

  // deriva chave c pbkdf2
  uint8_t chave_aes[CHAVE_TAMANHO];
  pbkdf2_hmac_sha256(
    (uint8_t*)user_senha,strlen(user_senha),
    salt, SALT_TAMANHO,
    ITER_PBKDF2,
    chave_aes, CHAVE_TAMANHO
    );

  // expandindo chave p subkeys aes 
  uint8_t subkeys_aes[TAM_MAX_CHAVE_EXPANDIDA];
  expansao_chave(chave_aes, subkeys_aes, NK_256);

  // limpando buffer
  memset(chave_aes, 0, CHAVE_TAMANHO);
  memset(user_senha, 0, sizeof(user_senha));

  // add salt e iv no arquivo de saida
  fwrite(salt, 1, SALT_TAMANHO, saida);
  fwrite(iv, 1, IV_TAMANHO, saida);

  // ler original p memoria.
  fseek(entry, 0, SEEK_END);
  size_t tam_original = ftell(entry);
  fseek(entry, 0, SEEK_SET);

  uint8_t *buffer_plain_text = malloc(tam_original + BLOCO_ENTRADA_TAM);
  if (!buffer_plain_text){
    perror("Erro ao alocar memória");
    exit(1);
  }

  fread(buffer_plain_text, 1, tam_original, entry);

  // add padding
  size_t tam_c_padding;
  padding_pkcs7(buffer_plain_text, tam_original, &tam_c_padding);

  // cifrando em cbc 
  uint8_t *buffer_txt_cifrado = malloc(tam_c_padding);
  if (!buffer_txt_cifrado){
    perror("Erro ao alocar memória");
    free(buffer_plain_text);
    exit(1);
  }

  cifra_cbc(buffer_plain_text, tam_c_padding, buffer_txt_cifrado, iv, subkeys_aes);

  // add cyphertext no arq de saida
  fwrite(buffer_txt_cifrado, 1, tam_c_padding, saida);

  // limpeza
  memset(buffer_plain_text, 0, tam_c_padding);
  memset(buffer_txt_cifrado, 0, tam_c_padding);
  memset(subkeys_aes, 0, TAM_MAX_CHAVE_EXPANDIDA);

  free(buffer_plain_text);
  free(buffer_txt_cifrado);

  fclose(entry);
  fclose(saida);

  printf("Arquivo %s cifrado com sucesso!", entry_path);
}

void decifragem_arquivo(const char *entry_path){
  FILE *entry = fopen(entry_path, "rb");
  if (!entry){
    perror("Impossível abrir arquivo\n");
    exit(1);
  }

  uint8_t salt_extract[SALT_TAMANHO];
  uint8_t iv_extract[IV_TAMANHO];

  // le salt
  if (fread(salt_extract, 1, SALT_TAMANHO, entry) != SALT_TAMANHO){
    fprintf(stderr, "Arquivo cifrado inválido\n(salt error)\n");
    exit(1);
  }

  // le iv 
  if(fread(iv_extract, 1, IV_TAMANHO, entry) != IV_TAMANHO){
    fprintf(stderr, "Arquivo cifrado inválido\n(iv error)\n");
    exit(1);
  }

  // le cyphertext
  fseek(entry, 0, SEEK_END);
  size_t tam_total = ftell(entry);
  size_t tam_cifrado = tam_total - SALT_TAMANHO - IV_TAMANHO;

  fseek(entry, SALT_TAMANHO + IV_TAMANHO, SEEK_SET);

  uint8_t *buffer_txt_cifrado = malloc(tam_cifrado);
  if (!buffer_txt_cifrado){
    perror("Erro ao alocar memória\n");
    exit(1);
  }

  // le ciphertetx 
  fread(buffer_txt_cifrado, 1, tam_cifrado, entry);
  fclose(entry);

  // pede a senha
  char try_senha[256];
  printf("Insira a senha do arquivo: ");
  if (!fgets(try_senha, sizeof(try_senha), stdin)) {
    fprintf(stderr, "Erro ao ler senha\n");
    exit(1);
  }

  try_senha[strcspn(try_senha, "\n")] = '\0';

  // deriva msm chave
  uint8_t chave_aes[CHAVE_TAMANHO];
  pbkdf2_hmac_sha256(
    (uint8_t*)try_senha, strlen(try_senha),
    salt_extract, SALT_TAMANHO,
    ITER_PBKDF2,
    chave_aes, CHAVE_TAMANHO
  );

  // expande chave
  uint8_t subkeys_aes[TAM_MAX_CHAVE_EXPANDIDA];
  expansao_chave(chave_aes, subkeys_aes, NK_256);

  // limpando
  memset(chave_aes, 0, CHAVE_TAMANHO);
  memset(try_senha, 0, sizeof(try_senha));

  // decifra cbc
  uint8_t *buffer_txt_decifrado = malloc(tam_cifrado);
  if (!buffer_txt_decifrado){
    perror("Erro ao alocar memória\n");
    free(buffer_txt_cifrado);
    exit(1);
  }

  decifra_cbc(buffer_txt_cifrado, tam_cifrado, buffer_txt_decifrado, iv_extract, subkeys_aes);

  // tira padding
  size_t tam_s_pad = tam_cifrado;
  if (unpadding_pkcs7(buffer_txt_decifrado, &tam_s_pad) != 0){
    fprintf(stderr, "Erro: padding inválido, senha incorreta ou arquivo corrompido\n");
    free(buffer_txt_cifrado);
    free(buffer_txt_decifrado);
    exit(1);
  }

  // mostra oq foi decifrado
  fwrite(buffer_txt_decifrado, 1, tam_s_pad, stdout);

  // limpa limpa limpa lalalala
  memset(buffer_txt_cifrado, 0, tam_cifrado);
  memset(buffer_txt_decifrado, 0, tam_cifrado);
  memset(subkeys_aes, 0, TAM_MAX_CHAVE_EXPANDIDA);

  free(buffer_txt_decifrado);
  free(buffer_txt_cifrado);

}

// teste 
void testar(){
  printf("///////// TESTE AES256 CBC //////////\n");
  printf("      ---(NIST SP 800-38A)---\n\n");

  uint8_t chave[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
  };

  uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };

  uint8_t plain_text[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
  };

  uint8_t resultado_esperado_cifra[32] = {
        0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
        0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
        0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
        0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d
  };

  uint8_t subkeys[TAM_MAX_CHAVE_EXPANDIDA];
  expansao_chave(chave, subkeys, NK_256);

  uint8_t cifra_calculada[32];
  cifra_cbc(plain_text, 32, cifra_calculada, iv, subkeys);

  if (memcmp(cifra_calculada, resultado_esperado_cifra, 32) == 0){
    printf("Sucesso na cifragem CBC >:D\n");
    printf("\nCifragem esperada:\n");
    for (int i = 0; i < 32; i++){
      printf("%02x", resultado_esperado_cifra[i]);
    }
    printf("\nCifragem obtida:\n");
    for (int i = 0; i < 32; i++){
      printf("%02x", cifra_calculada[i]);
    }
  } else {
    printf("Falha na cifragem CBC :/\n");
    printf("\nCifragem esperada:\n");
    for (int i = 0; i < 32; i++){
      printf("%02x", resultado_esperado_cifra[i]);
    }
    printf("\nCifragem obtida:\n");
    for (int i = 0; i < 32; i++){
      printf("%02x", cifra_calculada[i]);
    }
  }

  uint8_t decifra_calc[32];
  decifra_cbc(cifra_calculada, 32, decifra_calc, iv, subkeys);

  if(memcmp(decifra_calc, plain_text, 32) == 0){
    printf("\n\nSucesso na decifragem CBC :O\n");
    printf("\nDecifragem esperada:\n");
    for (int i = 0; i < 32; i++){
      printf("%02x", plain_text[i]);
    }
    printf("\nDecifragem obtida:\n");
    for (int i = 0; i < 32; i++){
      printf("%02x", decifra_calc[i]);
    }

  } else {
    printf("\n\nFalha na decifragem :(\n");
    printf("\nDecifragem esperada:\n");
    for (int i = 0; i < 32; i++){
      printf("%02x", plain_text[i]);
    }
    printf("\nDecifragem obtida:\n");
    for (int i = 0; i < 32; i++){
      printf("%02x", decifra_calc[i]);
    }
  }
    
  printf("\n\n////// Fim da operação //////\n");

}



// argc -> argument count 
// argv -> argument vector (string q fazem parte do comando)
// argv[0] = programa
// argv[1] = primeiro arugmento/comando
// argv[2] = arquivo
int main(int argc, char *argv[]){
  gerar_sbox();

  if (argc < 2){ // ve se há argumentos suficientes.
    printf("Uso:\n");
    printf("  %s cifrar <arquivo>\n", argv[0]);
    printf("  %s decifrar <arquivo.cifrado>\n", argv[0]);
    return 1;
  }

  if(strcmp(argv[1], "cifrar") == 0){
    if (argc < 3){
      fprintf(stderr, "Erro: indique o arquivo a ser cifrado\n");
      return 1;
    }
    cifragem_arquivo(argv[2]);
  } else if (strcmp(argv[1], "decifrar") == 0){
    if (argc < 3){
      fprintf(stderr, "Erro, indique o arquivo a ser decifrado\n");
      return 1;
    }
    decifragem_arquivo(argv[2]);
  } else if (strcmp(argv[1], "testar") == 0){
      testar();
  } else {
    fprintf(stderr, "Erro: comando desconhecido\n");
    return 1;
  }

  return 0;
}
