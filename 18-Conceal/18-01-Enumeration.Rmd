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

```{r, echo = FALSE, fig.cap="ike scan output", out.width="90%"}
    knitr::include_graphics("images/Conceal-ike-scan.png")
```

Aqui ya vemos todas las informaciones necessarias para podernos crear unos ficheros de configuracion para connectarnos por VPN.

### Creamos los ficheros de configuracion para la VPN {-}

Los dos ficheros que tenemos que tocar para configurar la VPN son:

- el fichero `/etc/ipsec.secrets` para la authentificacion
- el fichero `/etc/ipsec.conf` para la configuracion

Si buscamos por internet como se configura el fichero ipsec.secrets y encontramos algo el la web [systutorials](https://www.systutorials.com/docs/linux/man/5-ipsec.secrets)

```{r, echo = FALSE, fig.cap="info ipsec.secrets", out.width="90%"}
    knitr::include_graphics("images/Conceal-ipsec-secrets-web.png")
```

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


