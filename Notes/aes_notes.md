# /\ ADVANCED ENCRYPTION STANDARD /\
O AES é um algoritmo que **recebe um bloco de 128 bits, uma chave do tamanho escolhido e devolve uma cifra de 128 bits.**

Sua função inversa recebe a cifra de 128 bits e retorna um bloco de 128 bits. Caso seja a chave correta,  o resultado será idêntico ao bloco original.

O objetivo de uma boa cifra é que seja impossível encontrar a mensagem original sem a chave de criptografia.

Para isso, tenta-se minimizar qualquer semelhança entre a mensagem original e a saída em diversas rodadas, os bytes sofrem modificações não lineares, mas reversíveis.

Todas as operações dentro do AES tratam os bytes como um corpo finito, ou seja, há um conjunto "[0, 255]" que são todos os valores possíveis para um byte, sendo o elemento "zero" o próprio 0.

> As operações a seguir não possuem correlação com suas operações aritméticas homônimas.


## /\ ADIÇÃO /\ -> XOR ou "Ou exclusivo"

A operação de adição se aplica a quaisquer dois elementos do conjunto e seu resultado deve ser um elemento desse conjunto.
Essa operação precisa ser comutativa, associativa, ter elemento neutro e cada elemento ter um inverso.

## /\ MULTIPLICAÇÃO /\ -> AND

A operação q iremos chamar de multiplicação é semelhante a adição, mas seu elemento "zero" não possui inverso. Além disso o elementro neutro é chamado de "um".
Ademais, multiplicação também precisa ser distribuída em relação à adição.

**Passo a passo da Adição:**

1. Trate cada coperando como um polinônio com base na sua representação binária.<br>ex 1: 6 -> 110 em binário, então vira x²+x<br>110 ==> 4 + 2 + 0 ==> x² + 2 + 0<br> ex 2: 11 -> 1011 em binário, então vira x³ + x + 1<br>1011 ==> 8 + 0 + 2 + 1 ==> x³ + x  1
2. Multiplique-os e divida o resultado por um agente redutor.
3. Pegue o resto da divisão, este é o resultado da multiplicação.

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
