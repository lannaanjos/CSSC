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

// * ops a seguir sem correlação com os as operações aritméticas homonimas

/* /\/\/\/\/\ ADIÇÃO /\/\/\/\/\*/

// há uma operação chamada de adição que se aplica a            |
// quaisquer dois elementos do conjunto e cujo resultado        |
// deve ser um elemento desse conjunto                          |-> XOR ou "Ou exclusivo"                                                              
// a operação precisa ser comutativa, associativa, ter          |
// elemento neutro e cada elemento ter um inverso               |

/* /\/\/\/\/\ MULTIPLICAÇÃO /\/\/\/\/\*/

// há uma operação q iremos chamar de multiplicação             |
// ela é semelhante a adição, mas o elemento "zero"             |
// não possui inverso. além disso o elementro neutro            | -> AND
// é chamado de "um"                                            |
// a multiplicação tbm precisa ser distribuída em               |
// relação à adição                                             |

// 1. trate cada coperando como um polinônio com base na sua representação binária
// ex: 6 -> 110 em binário, então vira x²+x
// 110 ==> 4 + 2 + 0 ==> x² + 2 + 0

// ex: 11 -> 1011 em binário, então vira x³ + x + 1
// 1011 ==> 8 + 0 + 2 + 1 ==> x³ + x  1

// multiplique-os e divida o resultado por um agente redutor
// o resto da divisão é o resultado da multiplicação







#include <stdio.h>
#include <stdlib.h>

#define BITS_POR_BYTES 8