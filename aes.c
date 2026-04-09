//o aes é um algoritmo cuja função principal recebe um bloco de 128 bits, uma chave do tamanho escolhido
// edevolve uma cifra de 128 bits.

//a função inversa recebe a cifra de 128 bits e retorna um bloco de 128 bits, caso seja a chvae correta,
//vai ser identico ao bloco original

// o objetivo de uma cifra é que seja impossível encontrar a mensagem original somente com a cifra
// sem a chave de criptografia

// p isso, tenta-se minimizar qualquer semelhança entre a mensagem original e a saída
// em diversas rodadas, os bytes sofrem modificações não lineares, mas reversíveis

/*todas as operações dentro do aes tratam os bytes como um corpo finito, ou seja, 
há um conjunto [0, 255] que são todos os valores possíveis para um byte*/
// o elemento "zero" é o próprio 0





#include <stdio.h>
#include <stdlib.h>

#define BITS_POR_BYTES 8