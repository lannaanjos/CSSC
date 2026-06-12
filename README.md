# Criptografia e Segurança de Sistemas Computacionais

Repositório dedicado ao estudo e às atividades da disciplina.

Requisitos necessários para rodar: Sistema operacional Linux, gcc instalado

# Como rodar cada atividade

Dentro da pasta, abra o terminal e digite os comandos listados.

## SHA256 Puro
Fiz o SHA256 como Lib do Autenticador de Documentos, portanto acabei tendo que fazer um script de teste à parte para ele.
1. `cd Document_Authentication/`
2. `gcc -o sha256_teste sha256_teste.c sha256.c`
3. `./sha256_teste`

## Autenticador de Documentos
1. `cd Document_Authentication/`
2. `gcc -o authenticator authenticator.c sha256.c`
3. Para gerar: `./authenticator gerar <arquivo>`
4. Para verificar: `./authenticator verificar <arquivo> </arquivo> <hash>`

## RSA Puro
1. `cd rsa/`
2. `gcc -std=c99 -Wall bigint.c rsa.c -o rsa_teste` 
3. `./rsa_teste`

## RadiaTalk
Acabei não utilizando o RSA que implementei em C para o chat. Demoraria o dobro de tempo para implementar, e para desenvolver a interface pensei logo em usar Tkinter, então seria mais fácil fazer tudo em Python de qualquer forma.
Não tem nenhuma dependência externa, pode rodar direto com o Python seco instalado no computador.
1. Tenha dois terminais abertos na pasta.
2. Em ambos os terminais, dê `cd RadiaTalk/`.
3. Em ambos os terminais, escreva `python main.py`
4. Duas aplicações vão abrir. Por padrão, a sua porta local é 8080 e a esperada do "outro" é 8081. Basta deixar uma como está e a outra inverter as portas.
5. Em uma das aplicações, clique em aguardar, para esperar o handshake. Na outra, clique em conectar.
6. Pronto! Agora é só enviar as mensagens e ver aparecendo em ambas as telas. 

Para conectar em dispositivos diferentes:
1. Pegue o ip;
2. Deixe a porta normal para quem vai esperar o handshake.
3  Para a outra aplicaçãom troque "localhost" pelo IP (no campo url esperado) e clique em conectar. (ex: `http://192.168.1.105:8080`)

Se for no windows, o firewall pode dar problema, aí tem que liberar a porta automaticamente com o seguinte comando no PowerShell:
```
netsh advfirewall firewall add rule name="RadiaTalk" dir=in action=allow protocol=TCP localport=8080
```

Alt: Painel de Controle -> Firewall do Windows -> Regras de Entrada -> Nova Regra -> Porta -> TCP -> 8080
