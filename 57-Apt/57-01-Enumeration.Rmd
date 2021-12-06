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
