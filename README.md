# Criptografia e Segurança de Sistemas Computacionais

Repositório dedicado ao estudo e às atividades da disciplina.

**Requisitos Operacionais** para rodar as atividades: Sistema operacional Linux, gcc instalado

# Como rodar cada atividade

## RSA Puro
1. Entre em /CSSC/
2. `cd rsa`
3. `gcc -std=c99 -Wall bigint.c rsa.c -o rsa_teste` 
4. ./rsa_teste <- esse aqui é para rodar 

# conectar o radiatalk

1. pegar o ip
2. quem vai ligar o servidor escolhe a porta normal
3 quem vai conectar poe o servidor + a porta ex: `http://192.168.1.105:8080` e conecta

se for no windows, firewall pode dar problema, aí tem que liberar a porta automaticamente com
```
netsh advfirewall firewall add rule name="RadiaTalk" dir=in action=allow protocol=TCP localport=8080
```

ou

Painel de Controle → Firewall do Windows → Regras de Entrada → Nova Regra → Porta → TCP → 8080
