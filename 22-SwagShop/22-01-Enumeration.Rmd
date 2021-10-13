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

