# /\/\/\ main.py
# ponto de entrada do ZipZop
# orquestra: geração de chaves, servidor HTTP, cliente e interface Tkinter

from rsa       import gerar_chaves
from servidor  import Servidor
from cliente   import enviar_handshake, enviar_mensagem
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

# /\ AUXILIAR: prepara chaves e servidor

def _prepara(porta):
    """gera chaves RSA e sobe o servidor na porta dada"""
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

def on_aguardar(porta):
    """
    gera chaves, sobe servidor e aguarda o handshake do outro
    o handshake chega via POST /handshake no servidor
    quando chegar, on_handshake_recebido abre o chat
    """
    _prepara(porta)
    app.after(0, lambda: app._status("aguardando conexão...", erro=False))
    print("[main] aguardando handshake do outro lado...")


def on_conectar(porta, url_outro):
    """
    gera chaves, sobe servidor e inicia o handshake ativamente
    """
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


def on_enviar(texto):
    """envia mensagem cifrada para o outro"""
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


def on_mensagem_recebida(texto):
    """chamado pelo servidor ao receber e decifrar uma mensagem"""
    app.adicionar_mensagem('outro', texto)


def on_handshake_recebido():
    """
    chamado pelo servidor quando o outro faz POST /handshake
    armazena a chave do outro e abre o chat
    """
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
