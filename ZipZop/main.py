# /\/\/\ main.py
# ponto de entrada do ZipZop
# orquestra: geração de chaves, servidor HTTP, cliente e interface Tkinter

from rsa import gerar_chaves
from servidor import Servidor
from cliente import enviar_handshake, enviar_mensagem
from interface import App

# /\ ESTADO COMPARTILHADO

estado = {
    'chave_publica'       : None,
    'chave_privada'       : None,
    'chave_publica_outro' : None,
    'url_outro'           : None,
}

estado_servidor = {
    'chave_publica'       : None,
    'chave_privada'       : None,
    'chave_publica_outro' : None,
    'cb_mensagem'         : None,
    'cb_handshake'        : None,
}

servidor = None

# /\ AUX prepara chaves e servidor

# gera chave rsa e sobe server na porta dada
def _prepara(porta):
    global servidor

    print("[main] gerando chaves RSA...")
    pub, priv = gerar_chaves()
    estado['chave_publica'] = pub
    estado['chave_privada'] = priv
    estado_servidor['chave_publica'] = pub
    estado_servidor['chave_privada'] = priv

    print(f"[main] subindo servidor na porta {porta}...")
    servidor = Servidor(porta=porta, estado=estado_servidor)
    servidor.iniciar()

# /\ CALLBACKS
# gera chave, sobe server e espera handshake
# handshake chega via POSt /handshake no server
# qnd chega o handshake abre o chat
def on_aguardar(porta):
    _prepara(porta)
    app.after(0, lambda: app._status("aguardando conexão...", erro=False))
    print("[main] aguardando handshake do outro lado...")

# gera chaves, sobe server e inicia handshake
def on_conectar(porta, url_outro):
    global servidor

    estado['url_outro'] = url_outro
    _prepara(porta)

    print(f"[main] iniciando handshake com {url_outro}...")
    chave_outro = enviar_handshake(url_outro, estado['chave_publica'])

    if chave_outro is None:
        app.erro_conexao("handshake falhou: verifique a url e tente novamente")
        servidor.parar()
        servidor = None
        return

    estado['chave_publica_outro']          = chave_outro
    estado_servidor['chave_publica_outro'] = chave_outro

    print("[main] handshake concluído, chat pronto\n")
    app.conectado()

# manda msg cifrada p outro
def on_enviar(texto):
    chave_outro = estado['chave_publica_outro']
    url_outro   = estado['url_outro']

    if chave_outro is None or url_outro is None:
        print("[main] erro: handshake não realizado")
        return

    ok = enviar_mensagem(url_outro, texto, chave_outro)

    if ok:
        app.adicionar_mensagem('eu', texto)
    else:
        app.adicionar_mensagem_sistema("falha ao enviar mensagem")

# server chama ao receber e decifrar uma msg
def on_mensagem_recebida(texto):
    app.adicionar_mensagem('outro', texto)

# server chama qnd o outro faz post handshake
# guarda a chave do outro e abre o chat.
def on_handshake_recebido():
    print("[main] handshake recebido, chat pronto\n")

    # a chave do outro já foi salva no estado_servidor pelo handler
    # espelha para o estado local para uso no envio
    estado['chave_publica_outro'] = estado_servidor['chave_publica_outro']

    # url do outro: captura do campo da interface
    estado['url_outro'] = app.campo_url.get().strip()

    app.conectado()


# /\ MAIN
if __name__ == '__main__':
    estado_servidor['cb_mensagem']  = on_mensagem_recebida
    estado_servidor['cb_handshake'] = on_handshake_recebido

    app = App()
    app.cb_aguardar = on_aguardar
    app.cb_conectar = on_conectar
    app.cb_enviar   = on_enviar

    print("[main] ZipZop iniciado\n")
    app.mainloop()

    if servidor:
        servidor.parar()
