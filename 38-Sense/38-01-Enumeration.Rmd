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
