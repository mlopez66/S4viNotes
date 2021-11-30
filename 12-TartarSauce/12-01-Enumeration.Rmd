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


