# /\/\/\ ADVANCED ENCRYPTION STANDARD /\/\/\
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

/* /\/\/\ RIJNDAEL S-BOX /\/\/\*/

// a rijndael s-box é uma tabela de consulta para transformar bytes de forma não linear
// há a tabela para função direta e p inversa

// 1° calcule o inverso multiplicativo do byte  (byte que multiplicado por ele resulte em "um")
// 2° submeta os 8 bits de resultado a uma transformação afim, com intuito de ficar mais resistente
// contra ataque algébricos

/* /\/\/\ EXPANSÃO DA CHAVE /\/\/\*/
// o aes possui várias rodadas de cálculo sobre a mensagem inicial, aplica uma série de 
// transformações nela e chega ao resultado final (a cifra).
// os dados sendo trabalhados são o "state"

/*PSEUDOCÓDIGO

estado = mensagem
estado = round(mensagem)
estado = round(mensagem)
estado = round(mensagem)
...
estado = round(mensagem)
cifra = estado
*/

// não se usa a chave original em cada um dos estados, mas uma série de chaves derivadas da mesma
// aí precisa de um algoritmo de derivação de chave (argon2, pbkdf2, rijndael key schedule)

/* /\/\/\/\ VISÃO GERAL KEY DERIVATION /\/\/\/\*/
// o aes opera em blocos de 128 bits, entretanto usa chaves de 128, 192 ou 256 bits.
// o algoritmo de expansão de chaves faz um conjunto de subchaves de 128 bits, uma para cada round
// do algoritmo (q tbm depende do tamanho da chave: 10, 12 ou 14 respectivamente)

// a partir da chave original, são feitas uma série de operações de shift (rotação) dos últimos
// 4 bytes, sua transformação de acordo com o s-box e adição de potência de 2.
// qnd se produz bytes suficientes para todas as rodadas acaba a expansão