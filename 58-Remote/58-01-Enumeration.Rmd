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

