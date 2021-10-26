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
