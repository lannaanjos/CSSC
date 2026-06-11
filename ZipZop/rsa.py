# /\/\/\ rsa.py
# implementação do RSA em Python
# aproveita inteiros de precisão arbitrária nativos do Python
# sem necessidade de BigInt manual

import os
import sys

# /\ CONST
BITS_PRIMO  = 1024
E_PUBLICO   = 65537

# /\ MILLER-RABIN
# escreve n-1 como 2^r * d com d ímpar, retorna (r, d)
def _fatora_potencia_dois(n):
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r  += 1
    return r, d

# volta true se n passar no teste com testmunha a
def _miller_rabin_testemunha(n, a):
    r, d = _fatora_potencia_dois(n)
    x = pow(a, d, n)

    if x == 1 or x == n - 1:
        return True

    for _ in range(r - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return True

    return False

# testemunhas fixas: determinístico para n < 3.3 * 10^24
# para primos de 1024 bits o teste é probabilístico com erro < 4^-12
_TESTEMUNHAS = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

def eh_primo(n):
    if n < 2:  return False
    if n == 2: return True
    if n % 2 == 0: return False

    return all(_miller_rabin_testemunha(n, a) for a in _TESTEMUNHAS)

# /\ GERAÇÃO DE PRIMOS
# gera um primo aleatório de bits bits via os.urandom
def _gera_primo(bits):
    n_bytes = bits // 8

    while True:
        candidato = int.from_bytes(os.urandom(n_bytes), byteorder='big')

        # força bit mais significativo a 1: garante tamanho exato
        candidato |= (1 << (bits - 1))

        # força bit menos significativo a 1: garante ímpar
        candidato |= 1

        if eh_primo(candidato):
            return candidato

        # incrementa em 2 para manter ímpar e tentar o próximo candidato
        candidato += 2

# /\ GERAÇÃO DE CHAVES
# gera par de chaves de 2048 bits
# retorna public e private key
# privada = d, n
# publica = e, n
def gerar_chaves():
    print("[*] gerando primo p...")
    p = _gera_primo(BITS_PRIMO)

    print("[*] gerando primo q...")
    while True:
        q = _gera_primo(BITS_PRIMO)
        if q != p:
            break

    n   = p * q
    phi = (p - 1) * (q - 1)
    e   = E_PUBLICO

    # d = inverso modular de e em relação a phi(n) 
    d = pow(e, -1, phi)

    print("[ok] chaves geradas\n")

    chave_publica  = (e, n)
    chave_privada  = (d, n)

    return chave_publica, chave_privada

# /\ CIFRAGEM E DECIFRAGEM

# cifra o int m com a public key
# resultado = m^e mod n, e obrigatório m < n
def cifrar(m, chave_publica):
    e, n = chave_publica
    return pow(m, e, n)

# decifra o int c com a private key
# resultado = c^d mod n
def decifrar(c, chave_privada):

    d, n = chave_privada
    return pow(c, d, n)

# /\ SERIALIZAÇÃO DE MENSAGENS
# tamanho do bloco em bytes: 2048 bits = 256 bytes
# cada mensagem é cifrada como um inteiro menor que n
BLOCO_BYTES = 256

def texto_para_inteiro(texto):
    # converte string utf-8 para inteiro
    return int.from_bytes(texto.encode('utf-8'), byteorder='big')

def inteiro_para_texto(valor):
    # converte inteiro de volta para string utf-8
    n_bytes = (valor.bit_length() + 7) // 8
    return valor.to_bytes(n_bytes, byteorder='big').decode('utf-8')

# cifra uma string com a public key
# retorna o ciphertext como string hex p transmissão
def cifrar_mensagem(texto, chave_publica):
    m = texto_para_inteiro(texto)
    c = cifrar(m, chave_publica)
    hex_c = hex(c)[2:]  # remove o prefixo '0x'
    print(f"[rsa] mensagem cifrada: {hex_c[:64]}...")
    return hex_c

# decifra uma string hex com a private key
# retorna texto original
def decifrar_mensagem(hex_c, chave_privada):
    print(f"[rsa] mensagem criptografada recebida: {hex_c[:64]}...")
    c = int(hex_c, 16)
    m = decifrar(c, chave_privada)
    texto = inteiro_para_texto(m)
    print(f"[rsa] mensagem descriptografada: {texto}")
    return texto

# /\ SERIALIZAÇÃO DE CHAVES
# serializa (e,n) como 'hex_e:hex_n' p handshake
def chave_publica_para_hex(chave_publica):
    e, n = chave_publica
    return f"{hex(e)[2:]}:{hex(n)[2:]}"

# desserializa 'hex_e:hex_n' p (e,n)
def chave_publica_de_hex(s):
    partes = s.split(':')
    if len(partes) != 2:
        raise ValueError("formato de chave pública inválido")
    e = int(partes[0], 16)
    n = int(partes[1], 16)
    return (e, n)

# /\/\/\ TESTE
'''if __name__ == '__main__':
    print("///////// TESTE RSA no PyPy /////////\n")

    pub, priv = gerar_chaves()

    mensagem = "Salve ZipZop"
    print(f"[*] mensagem original : {mensagem}")

    hex_cifrado = cifrar_mensagem(mensagem, pub)
    recuperada  = decifrar_mensagem(hex_cifrado, priv)

    print(f"\n[*] mensagem recuperada: {recuperada}")

    if mensagem == recuperada:
        print("\n[sucessinho]: mensagem decifrada bate com a original !")
    else:
        print("\n[falha aff] mensagem decifrada NAO bate com a original !!!!!!")

    print("\n:O cabou-se\n")'''
