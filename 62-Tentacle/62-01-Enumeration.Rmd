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


```{r, echo = FALSE, fig.cap="normal proxychains", out.width="90%"}
    knitr::include_graphics("images/Tentacle-normal-proxychains-conf.png")
```

Pasamos por internet para con el Squid Proxy scanear el 10.197.243.77. Pensamos que es un **Internal Squid Proxy** porque el dominio es 
`proxy.realcorp.htb`. Hemos podido comprobar que esta tecnica no funcciona.

Lo que queremos hacer es uzar otra configuracion del proxychains para que pasemos por el Squid Proxy hacia la interface interna del puerto 3128
de este mismo Squid Proxy.
pero de manera local para poder scanear el **Internal Squid Proxy**.



```{r, echo = FALSE, fig.cap="isp proxychains", out.width="90%"}
    knitr::include_graphics("images/Tentacle-isp-proxychains-conf.png")
```

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

```{r, echo = FALSE, fig.cap="internal servers scanning", out.width="90%"}
    knitr::include_graphics("images/Tentacle-otherserv-proxychains-conf.png")
```

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

```{r, echo = FALSE, fig.cap="Proxychains chain", out.width="90%"}
    knitr::include_graphics("images/Tentacle-proxychains-chain.png")
```

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

```{r, echo = FALSE, fig.cap="wpad.dat", out.width="90%"}
    knitr::include_graphics("images/Tentacle-wpad-dat.png")
```

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
