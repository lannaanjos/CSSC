# /\/\/\ interface.py
# interface gráfica do ZipZop
# layout flat e funcional, paleta azul bebê
# duas telas: conexão e chat

import tkinter as tk
from tkinter import scrolledtext
import threading

# /\ PALETA

COR_FUNDO        = "#D6EAF5"  # azul gelo (fundo geral)
COR_BOTAO        = "#4A86A8"  # azul escuro (botões)
COR_BOTAO_HOVER  = "#3A6A8A"  # azul escuro hover
COR_TEXTO        = "#1C3A4A"  # marinho (texto geral)
COR_TEXTO_BRANCO = "#FFFFFF"  # branco (texto em botões)
COR_ENTRADA      = "#FFFFFF"  # branco (campos de entrada)
COR_EU           = "#4A86A8"  # mensagem própria
COR_OUTRO        = "#7AAFC7"  # mensagem do outro
COR_SYS          = "#7AAFC7"  # mensagem de sistema
COR_STATUS_OK    = "#2E7D52"  # verde status ok
COR_STATUS_ERR   = "#A03030"  # vermelho status erro

# /\ JANELA PRINCIPAL

class App(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("ZipZop")
        self.geometry("360x500")
        self.resizable(False, False)
        self.configure(bg=COR_FUNDO)

        # callbacks injetados pelo main.py
        self.cb_aguardar = None  # fn(porta)
        self.cb_conectar = None  # fn(porta, url_outro)
        self.cb_enviar   = None  # fn(texto)

        self._constroi_tela_conexao()
        self._constroi_tela_chat()
        self._mostra_conexao()

    # /\ TELA DE CONEXÃO

    def _constroi_tela_conexao(self):
        self.frame_conexao = tk.Frame(self, bg=COR_FUNDO)

        tk.Label(
            self.frame_conexao,
            text="ZipZop",
            font=("Courier", 22, "bold"),
            bg=COR_FUNDO, fg=COR_TEXTO
        ).pack(pady=(40, 4))

        tk.Label(
            self.frame_conexao,
            text="chat cifrado P2P",
            font=("Helvetica", 9),
            bg=COR_FUNDO, fg=COR_BOTAO
        ).pack(pady=(0, 32))

        # porta local
        tk.Label(
            self.frame_conexao,
            text="porta local",
            font=("Helvetica", 8, "bold"),
            bg=COR_FUNDO, fg=COR_TEXTO, anchor='w'
        ).pack(fill='x', padx=40)

        self.campo_porta = tk.Entry(
            self.frame_conexao,
            font=("Courier", 10),
            bg=COR_ENTRADA, fg=COR_TEXTO,
            relief='flat', bd=1,
            insertbackground=COR_TEXTO
        )
        self.campo_porta.insert(0, "8080")
        self.campo_porta.pack(fill='x', padx=40, pady=(2, 14))

        # url do outro
        tk.Label(
            self.frame_conexao,
            text="url do outro",
            font=("Helvetica", 8, "bold"),
            bg=COR_FUNDO, fg=COR_TEXTO, anchor='w'
        ).pack(fill='x', padx=40)

        self.campo_url = tk.Entry(
            self.frame_conexao,
            font=("Courier", 10),
            bg=COR_ENTRADA, fg=COR_TEXTO,
            relief='flat', bd=1,
            insertbackground=COR_TEXTO
        )
        self.campo_url.insert(0, "http://localhost:8081")
        self.campo_url.pack(fill='x', padx=40, pady=(2, 20))

        # botões aguardar e conectar lado a lado
        frame_btns = tk.Frame(self.frame_conexao, bg=COR_FUNDO)
        frame_btns.pack(fill='x', padx=40)

        self.btn_aguardar = tk.Button(
            frame_btns,
            text="aguardar",
            font=("Courier", 10, "bold"),
            bg=COR_BOTAO, fg=COR_TEXTO_BRANCO,
            relief='flat', cursor='hand2',
            activebackground=COR_BOTAO_HOVER,
            activeforeground=COR_TEXTO_BRANCO,
            pady=8,
            command=self._on_aguardar
        )
        self.btn_aguardar.pack(side='left', fill='x', expand=True, padx=(0, 4))

        self.btn_conectar = tk.Button(
            frame_btns,
            text="conectar",
            font=("Courier", 10, "bold"),
            bg=COR_BOTAO, fg=COR_TEXTO_BRANCO,
            relief='flat', cursor='hand2',
            activebackground=COR_BOTAO_HOVER,
            activeforeground=COR_TEXTO_BRANCO,
            pady=8,
            command=self._on_conectar
        )
        self.btn_conectar.pack(side='left', fill='x', expand=True, padx=(4, 0))

        # status
        self.label_status = tk.Label(
            self.frame_conexao,
            text="",
            font=("Helvetica", 8),
            bg=COR_FUNDO, fg=COR_STATUS_ERR,
            wraplength=280
        )
        self.label_status.pack(pady=(12, 0))

    def _valida_porta(self):
        porta_str = self.campo_porta.get().strip()
        if not porta_str.isdigit():
            self._status("porta inválida", erro=True)
            return None
        return int(porta_str)

    def _bloqueia_botoes(self):
        self.btn_aguardar.config(state='disabled')
        self.btn_conectar.config(state='disabled')

    def _desbloqueia_botoes(self):
        self.btn_aguardar.config(state='normal', text="aguardar")
        self.btn_conectar.config(state='normal', text="conectar")

    def _on_aguardar(self):
        porta = self._valida_porta()
        if porta is None:
            return

        self._bloqueia_botoes()
        self.btn_aguardar.config(text="aguardando...")
        self._status("gerando chaves e subindo servidor...", erro=False)

        if self.cb_aguardar:
            threading.Thread(
                target=self.cb_aguardar,
                args=(porta,),
                daemon=True
            ).start()

    def _on_conectar(self):
        porta = self._valida_porta()
        if porta is None:
            return

        url_outro = self.campo_url.get().strip()
        if not url_outro.startswith("http"):
            self._status("url inválida", erro=True)
            return

        self._bloqueia_botoes()
        self.btn_conectar.config(text="conectando...")
        self._status("gerando chaves RSA...", erro=False)

        if self.cb_conectar:
            threading.Thread(
                target=self.cb_conectar,
                args=(porta, url_outro),
                daemon=True
            ).start()

    def _status(self, texto, erro=False):
        cor = COR_STATUS_ERR if erro else COR_STATUS_OK
        self.label_status.config(text=texto, fg=cor)

    # /\ TELA DE CHAT

    def _constroi_tela_chat(self):
        self.frame_chat = tk.Frame(self, bg=COR_FUNDO)

        self.area_msgs = scrolledtext.ScrolledText(
            self.frame_chat,
            font=("Courier", 9),
            bg=COR_ENTRADA, fg=COR_TEXTO,
            relief='flat', bd=0,
            state='disabled',
            wrap='word',
            cursor='arrow',
            padx=8, pady=8
        )
        self.area_msgs.pack(fill='both', expand=True, padx=16, pady=(16, 8))

        self.area_msgs.tag_config('eu',    foreground=COR_EU,    font=("Courier", 9, "bold"))
        self.area_msgs.tag_config('outro', foreground=COR_OUTRO, font=("Courier", 9, "bold"))
        self.area_msgs.tag_config('sys',   foreground=COR_SYS,   font=("Courier", 8, "italic"))

        frame_input = tk.Frame(self.frame_chat, bg=COR_FUNDO)
        frame_input.pack(fill='x', padx=16, pady=(0, 16))

        self.campo_msg = tk.Entry(
            frame_input,
            font=("Courier", 10),
            bg=COR_ENTRADA, fg=COR_TEXTO,
            relief='flat', bd=1,
            insertbackground=COR_TEXTO
        )
        self.campo_msg.pack(side='left', fill='x', expand=True, ipady=6)
        self.campo_msg.bind("<Return>", lambda e: self._on_enviar())

        tk.Button(
            frame_input,
            text="enviar",
            font=("Courier", 9, "bold"),
            bg=COR_BOTAO, fg=COR_TEXTO_BRANCO,
            relief='flat', cursor='hand2',
            activebackground=COR_BOTAO_HOVER,
            activeforeground=COR_TEXTO_BRANCO,
            padx=12, pady=6,
            command=self._on_enviar
        ).pack(side='left', padx=(6, 0))

    def _on_enviar(self):
        texto = self.campo_msg.get().strip()
        if not texto:
            return

        self.campo_msg.delete(0, 'end')

        if self.cb_enviar:
            threading.Thread(
                target=self.cb_enviar,
                args=(texto,),
                daemon=True
            ).start()

    # /\ TROCA DE TELAS

    def _mostra_conexao(self):
        self.frame_chat.pack_forget()
        self.frame_conexao.pack(fill='both', expand=True)

    def _mostra_chat(self):
        self.frame_conexao.pack_forget()
        self.frame_chat.pack(fill='both', expand=True)

    # /\ API PÚBLICA

    def conectado(self):
        self.after(0, self._mostra_chat)
        self.after(0, lambda: self.adicionar_mensagem_sistema("conexão estabelecida"))

    def erro_conexao(self, motivo):
        self.after(0, self._desbloqueia_botoes)
        self.after(0, lambda: self._status(motivo, erro=True))

    def adicionar_mensagem(self, remetente, texto):
        def _insere():
            self.area_msgs.config(state='normal')
            tag     = 'eu' if remetente == 'eu' else 'outro'
            prefixo = "você" if remetente == 'eu' else "outro"
            self.area_msgs.insert('end', f"{prefixo}: ", tag)
            self.area_msgs.insert('end', f"{texto}\n")
            self.area_msgs.config(state='disabled')
            self.area_msgs.see('end')
        self.after(0, _insere)

    def adicionar_mensagem_sistema(self, texto):
        def _insere():
            self.area_msgs.config(state='normal')
            self.area_msgs.insert('end', f"-- {texto} --\n", 'sys')
            self.area_msgs.config(state='disabled')
            self.area_msgs.see('end')
        self.after(0, _insere)
