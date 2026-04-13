# /\ ADVANCED ENCRYPTION STANDARD /\
O AES é um algoritmo que **recebe um bloco de 128 bits, uma chave do tamanho escolhido e devolve uma cifra de 128 bits.**Sua função inversa recebe a cifra de 128 bits e retorna um bloco de 128 bits. Caso seja a chave correta,  o resultado será idêntico ao bloco original.
Ou seja, ele é um cifrador de bloco simétrico, o que quer dizer que a mesma chave é usada para cifrar e decifrar.
O objetivo de uma boa cifra é que seja impossível encontrar a mensagem original sem a chave de criptografia.

Para isso, tenta-se minimizar qualquer semelhança entre a mensagem original e a saída em diversas rodadas, os bytes sofrem modificações não lineares, mas reversíveis.

Todas as operações dentro do AES tratam os bytes como um corpo finito, ou seja, há um conjunto "[0, 255]" que são todos os valores possíveis para um byte, sendo o elemento "zero" o próprio 0.

> As operações a seguir não possuem correlação com suas operações aritméticas homônimas.


## /\ ADIÇÃO -> XOR ou "Ou exclusivo" /\

A operação de adição se aplica a quaisquer dois elementos do conjunto e seu resultado deve ser um elemento desse conjunto.
Essa operação precisa ser comutativa, associativa, ter elemento neutro e cada elemento ter um inverso.

## /\ MULTIPLICAÇÃO -> GF(2⁸) /\

A operação q iremos chamar de multiplicação é semelhante a adição, mas seu elemento "zero" não possui inverso. Além disso o elementro neutro é chamado de "um".
Ademais, multiplicação também precisa ser distribuída em relação à adição.
Ela é uma multiplicação de polinômios em GF(2⁸), o corpo de Galois de 256 elementos.
**Passo a passo da Multiplicação:**

1. Trate cada coperando como um polinônio com base na sua representação binária.<br>ex: 6 -> 110 em binário, então vira x²+x<br>110 ==> 4 + 2 + 0 ==> x² + 2 + 0<br><br> ex : 11 -> 1011 em binário, então vira x³ + x + 1<br>1011 ==> 8 + 0 + 2 + 1 ==> x³ + x  1
2. Multiplique-os e divida o resultado por um agente redutor.
3. Pegue o resto da divisão, este é o resultado da multiplicação.

Seu objetivo é receber dois bytes e retornar um byte, e ser reversível (exceto para o zero).
Ao invés de tratar um byte como um número inteiro, o tratamos como um polinômio cujos coeficientes são 0 ou 1. Multiplicar dois bytes é, então, multiplicar os dois polinômios, com a regra de que os polinômios são calculados em módulo 2.
Entretanto, `x⁵ + x⁴ + x³ + + x` tem grau 5, e não cabe em um byte (bytes suportam até grau 7, mas o resultado da multiplicação pode extrapolar seu tamnho máximo).
Por isso, a solução é dividir o resultado pelo módulo fixo ``x⁸ + x⁴ + x³ + x + 1`` e ficar com o resto. Isso garante que o grau do resultado nunca passe de 7 e sempre caiba em um byte.
O polinômio escolhido foi escolhido pelos criadores do AES por ser irredutível, ele não tem fatores, o que garante que todos elemente não-nulo tenha um inverso multiplicativo.
Essa multiplicação é usada no MixColumns do AES, combinando com os valores *1, 2, 3*.
Um atalho para isso é a função, normalmente, denominada ``xtime``. Com ela, deslocamos o byte 1 bit à esquerda. Se o bit mais significativo era 1, é feito o XOR com 0x1b.

```
uint8_t xtime(uint8_t a){
  return (a << 1) ^((a & 0x80) ? 0x1b : 0x00);
}
```

Qualquer multiplicação maior se constrói a partir daí, por exemplo:

```
a x 3 = a x (2 + 1) = xtime(a) XOR a 
a x 4 = xtime(xtime(a))
a x 5 = xtime(xtime(a)) XOR a 
```
## /\ RIJNDAEL S-BOX /\

A rijndael s-box é uma tabela de consulta para transformar bytes de forma não linear. Existe a tabela para função direta e para a inversa.

**Passo a passo da Rijndael S-Box:**

1. Calcule o inverso multiplicativo do byte (byte que multiplicado por ele resulte em "um").
2. Submeta os 8 bits de resultado a uma transformação afim, com intuito de ficar mais resistente contra ataque algébricos.

## /\ EXPANSÃO DA CHAVE /\
O AES possui várias rodadas de cálculo sobre a mensagem inicial. Aplica-se uma série de transformações nela e chega-se ao resultado final (a cifra).
Os dados que estão sendo trabalhados são denominados como "state".

```
# PSEUDOCÓDIGO:

estado = mensagem
estado = round(estado)
estado = round(estado)
estado = round(estado)
...
estado = round(estado)
cifra = estado
```

Não se usa a chave original em cada um dos estados, mas uma série de chaves derivadas da mesma. Para isso, é preciso um algoritmo de derivação de chave.
**OBS:** Rijndael Key Schedule é o algoritmo de expansão de chave interno do AES. Argon2, PBKDF2 são KDFs de senha, usados para derivar chaves a partir de senhas humanas.

# /\ VISÃO GERAL KEY DERIVATION /\
O AES opera em blocos de 128 bits, entretanto usa chaves de 128, 192 ou 256 bits.
O algoritmo de expansão de chaves faz um conjunto de subchaves de 128 bits, uma para cada round do algoritmo (que também depende do tamanho da chave: 10, 12 ou 14 respectivamente).
A partir da chave original, são feitas uma série de operações de shift (rotação) dos últimos 4 bytes, sua transformação de acordo com o S-Box e adição de potência de 2.
Ao produzir bytes suficientes para todas as rodadas acaba a expansão.

## /\ RODADAS /\
Para evitar que a encriptação seja quebrada na força bruta, são feitas várias rodadas em cima do estado. O objetivo é que os bytes da entrada sejam combinados com os vários bytes da chave.
Ou seja, busca-se evitar que parte da cifra depende somente de parte da chave de encriptação.
Os bytes do estado são armazenados numa matriz 4x4 por coluna.
Ex:
```
b0  b4  b8  b12 
b1  b5  b9  b13 
b2  b6  b10 b14 
b3  b7  b11 b15 
```

**Passo a passo das rodadas:**
1. O estado é adicionado à chave da rodada.<br>``estado = estado ^ chave(0)``
2. Nas rodadas seguintes, cada byte do estado é transformado conforme o S-Box.<br>``Para cada byte b no estado:<br> estado[b] = S(estado[b])``
3. Depois as linhas são rotacionadas à esquerda.
4. Depois, em cada coluna da matriz, os bytes são combinados com todos os demais bytes da mesma coluna (OBS: Isso não ocorre na última rodada).
5. Ao final, a chave da rodada é somada ao estado.

## /\ DECIFRAGEM /\
O processo de decifragem consiste basicamente no inverso das etapas anteriormente mostradas.
**Passo a passo:**
1. No início de cada rounds, adiciona-se a chave do round correspondente (que agora estão de trás para frente).
2. Para desfazer a mistura de colunas, usa-se a matriz inversa.
3. Faz-se um shift para a direita.
4. E, por fim, para desfazer a primeira etapa faz-se uso de uma tabela S-Box invertida.
