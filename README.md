## Referências:
1. Explicação AES: https://pt.stackoverflow.com/questions/43492/como-funciona-o-algoritmo-de-criptografia-aes

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