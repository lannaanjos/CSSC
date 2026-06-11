# /\/\/\ cliente.py
# cliente HTTP: envia handshake e mensagens cifradas para o outro usuário

import json
import urllib.request
import urllib.error

from rsa import chave_publica_para_hex, chave_publica_de_hex, cifrar_mensagem

# /\ HANDSHAKE

def enviar_handshake(url_outro, chave_publica_propria):
    """
    envia a própria chave pública para o outro via POST /handshake
    retorna a chave pública do outro como (e, n), ou None em falha
    """
    url  = f"{url_outro.rstrip('/')}/handshake"
    body = json.dumps({
        'chave_publica': chave_publica_para_hex(chave_publica_propria)
    }).encode('utf-8')

    print(f"[cliente] enviando handshake para {url}...")

    try:
        req      = urllib.request.Request(url, data=body,
                       headers={'Content-Type': 'application/json'},
                       method='POST')
        with urllib.request.urlopen(req, timeout=10) as resp:
            dados = json.loads(resp.read().decode('utf-8'))
            chave = chave_publica_de_hex(dados['chave_publica'])
            print(f"[cliente] handshake ok: chave pública do outro recebida")
            return chave

    except urllib.error.URLError as e:
        print(f"[cliente] erro de conexão no handshake: {e}")
        return None
    except Exception as e:
        print(f"[cliente] erro inesperado no handshake: {e}")
        return None

# /\ ENVIO DE MENSAGEM

def enviar_mensagem(url_outro, texto, chave_publica_outro):
    """
    cifra texto com a chave pública do outro e envia via POST /mensagem
    retorna True em sucesso, False em falha
    """
    print(f"[cliente] enviando mensagem...")

    hex_c = cifrar_mensagem(texto, chave_publica_outro)
    url   = f"{url_outro.rstrip('/')}/mensagem"
    body  = json.dumps({'mensagem': hex_c}).encode('utf-8')

    try:
        req = urllib.request.Request(url, data=body,
                  headers={'Content-Type': 'application/json'},
                  method='POST')
        with urllib.request.urlopen(req, timeout=10) as resp:
            dados = json.loads(resp.read().decode('utf-8'))
            if dados.get('ok'):
                print(f"[cliente] mensagem entregue")
                return True
            else:
                print(f"[cliente] servidor recusou a mensagem: {dados}")
                return False

    except urllib.error.URLError as e:
        print(f"[cliente] erro de conexão ao enviar mensagem: {e}")
        return False
    except Exception as e:
        print(f"[cliente] erro inesperado ao enviar mensagem: {e}")
        return False
