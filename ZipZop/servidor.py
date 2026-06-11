# /\/\/\ servidor.py
# servidor HTTP embutido que roda em thread separada
# recebe handshake e mensagens cifradas do outro usuário

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from rsa import chave_publica_para_hex, chave_publica_de_hex, decifrar_mensagem

# /\ HANDLER

def _cria_handler(estado):
    """
    fábrica do handler: injeta o estado compartilhado via closure
    estado é um dict com:
        'chave_publica'       : (e, n) própria
        'chave_privada'       : (d, n) própria
        'chave_publica_outro' : (e, n) do outro (None até o handshake)
        'cb_mensagem'         : callback chamado ao receber mensagem (texto)
        'cb_handshake'        : callback chamado ao completar handshake
    """

    class Handler(BaseHTTPRequestHandler):

        def _responde(self, codigo, corpo):
            corpo_bytes = corpo.encode('utf-8')
            self.send_response(codigo)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(corpo_bytes))
            self.end_headers()
            self.wfile.write(corpo_bytes)

        def _le_corpo(self):
            tam = int(self.headers.get('Content-Length', 0))
            return self.rfile.read(tam).decode('utf-8')

        def do_POST(self):
            if self.path == '/handshake':
                self._handle_handshake()
            elif self.path == '/mensagem':
                self._handle_mensagem()
            else:
                self._responde(404, json.dumps({'erro': 'endpoint desconhecido'}))

        def _handle_handshake(self):
            corpo = self._le_corpo()

            try:
                dados = json.loads(corpo)
                chave_hex = dados['chave_publica']
                estado['chave_publica_outro'] = chave_publica_de_hex(chave_hex)
                print(f"[servidor] handshake recebido: chave pública do outro armazenada")
            except Exception as e:
                print(f"[servidor] erro no handshake: {e}")
                self._responde(400, json.dumps({'erro': str(e)}))
                return

            # responde com a própria chave pública
            resposta = json.dumps({
                'chave_publica': chave_publica_para_hex(estado['chave_publica'])
            })
            self._responde(200, resposta)

            if estado.get('cb_handshake'):
                estado['cb_handshake']()

        def _handle_mensagem(self):
            if estado['chave_publica_outro'] is None:
                self._responde(403, json.dumps({'erro': 'handshake não realizado'}))
                return

            corpo = self._le_corpo()

            try:
                dados    = json.loads(corpo)
                hex_c    = dados['mensagem']
                print(f"[servidor] mensagem criptografada recebida: {hex_c[:64]}...")
                texto    = decifrar_mensagem(hex_c, estado['chave_privada'])
            except Exception as e:
                print(f"[servidor] erro ao decifrar mensagem: {e}")
                self._responde(400, json.dumps({'erro': str(e)}))
                return

            self._responde(200, json.dumps({'ok': True}))

            if estado.get('cb_mensagem'):
                estado['cb_mensagem'](texto)

        # silencia os logs padrão do HTTPServer no terminal
        def log_message(self, format, *args):
            pass

    return Handler

# /\ SERVIDOR

class Servidor:

    def __init__(self, porta, estado):
        self._porta   = porta
        self._estado  = estado
        self._httpd   = None
        self._thread  = None

    def iniciar(self):
        handler      = _cria_handler(self._estado)
        self._httpd  = HTTPServer(('0.0.0.0', self._porta), handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        print(f"[servidor] escutando na porta {self._porta}")

    def parar(self):
        if self._httpd:
            self._httpd.shutdown()
            print(f"[servidor] encerrado")
