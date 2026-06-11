# Rivest-Shamir-Adleman Cryptosystem

Numa criptografia baseada em RSA, a chave privada do usuário é par de números primos enormes escolhidos aleatoriamente. A chave pública do usuário é o produto desses números primos.

> Multiplicar dois primos grandes é simples, mas fatorar o resultado de volta nos dois primos é praticamente impossível para números grandes o bastante.

## Etapas

1. Geração de chaves:
  a. Escolhe dois primos grandes `p` e `q`.
  b. Calcula `n = p * q`. O `n` é o módulo que vai aparecer em tudo, e é o tamanho da chave RSA.
  c. Calcula a totiente de Carmichael:

  ```
  φ(n) = (p - 1) * (q - 1)
  ```

  d. Escolhe o expoente público tal que:
    - `1 < e < φ(n)`
    - `mdc(e, φ(n)) = 1`
  e. Calcula o expoente público que é o inverso modular de `e` em relação ao `φ(n)`:
  ```
  d * e ≡ 1 (mod φ(n))
  ```

2. Cifragem e Decifragem
  a. Cifragem: `c = m^e mod n`
  b. Decifragem: `m = c^d mod n` (só quem tem `d` consegue recuperar a mensagem)

