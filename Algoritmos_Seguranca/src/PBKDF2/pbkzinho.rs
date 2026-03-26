// pbkdf2 é uma função de derivação de chave q serve para transformar uma senha comum em uma chave criptográfica forte

// funcionamento:
/*recebe os argumentos:
-senha (p) -> assim q a senha é criada, é atribuído um salt a ela
-salt (s) -> sequencia de bits, string appendada na senha| serve para que o hash não seja duplicado, para que não seja gerado hash igual
-iterações(c) -> n° de repetições | roda a senha+salt numa função hash
-função hash -> algoritmo matematico q transforma um valor de tamanho variavel em um hash, q é uma estrutura de tamanho fixo
-tamanho da chave -> em bits
*/

/* formula:
 DK = T1 || T2 || ... || Tn
 Caba bloco é calculado assim:

Ti = U1 xor U2 xor ... xor Un

U1 = H(p s i)
U2 = H(P, U1)
U3 = H(P, U2)
Un = H(P, Un-1)

a saída anterior é entrada da próxima iteração
 */


 /*mistura senha + salt
 aplica hash
 repete isso milhares de vezes
 combina os resultados com xor
 
 */



