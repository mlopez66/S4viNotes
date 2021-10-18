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


