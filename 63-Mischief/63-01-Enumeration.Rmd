## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.92
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.92
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.92 -oG allPorts 
extractPorts allPorts
nmap -sCV -p22,3366 10.10.10.92 -oN targeted
```


| Puerto | Servicio                                         | Que se nos occure? | Que falta? |
| ------ | ------------------------------------------------ | ------------------ | ---------- |
| 22     | ssh                                              | Coneccion directa  |            |
| 3366   | http calandar and contacts python BaseHTTPServer |                    |            |


### Analysando el BaseHTTPServer {-}

Con firefox entramos la url `http://10.10.10.92:3366`. Vemos un panel basic auth. Intentamos credenciales
por defecto

```bash
admin:admin
guest:guest
riley:reid
```

No podemos connectar pero encontramos una cadena en base64

```bash
echo "cmlsZXk6cmVpZA==" | base64 -d; echo

#Output
riley:reid
```

Parece que nos reporta la credenciales entradas por base64.

#### Whatweb {-}

```bash
whatweb http://10.10.10.92:3366/
```

vemos que es Python 2.7.15rc1 con un WWW-Authenticate pero nada mas. Como cada intento de routa con firefox nos lleva al panel de
authenticacion, Fuzzear no tiene sentido.

### Scaneando por UDP {-}

```bash
nmap -sU --top-ports 500 -v -n 10.10.10.92
```

encontramos el puerto 161 abierto

```bash
nmap -sCV -p161 -sU 10.10.10.92 -oN udpScan
```

### Enumerando el snmp {-}

```bash
onesixtyone 10.10.10.92 -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt
```

Vemos que la community string es **public**


```bash
snmpwalk -v2c -c public 10.10.10.92
snmpwalk -v2c -c public 10.10.10.92 ipAddressType
```

Aqui no vemos nada muy interessante. Lo unico es la IPV6 address de la maquina.
Podemos intentar scanear con nmap con la IPV6. Primero tenemos que tocar la ip

```bash
de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:b9:55:91
dead:beef:0250:56ff:feb9:5591
ping -c 1 dead:beef:0250:56ff:feb9:5591
nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn -6 dead:beef:0250:56ff:feb9:5591 -oG allPortsipv6
extractPorts allPortsipv6
nmap -sCV -p22,80 -6 dead:beef:0250:56ff:feb9:5591 -oN targetedipv6
```

| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | ssh      | Coneccion directa  |            |
| 80     | http     |                    |            |


### Analysando la web en ipv6 {-}

Con firefox se puede ver ipv6 poniendo la ip entre corchetes `[dead:beef:0250:56ff:feb9:5591]` y vemos un panel
de authenticacion. Intentamos credenciales por defecto pero no encontramos nada.

### SNMPWALK mas contundente {-}

Como sabemos que el puerto 3366 es un SimpleHTTPServer de python2.7, miramos si podemos 
recuperar mas informaciones para este servicio

```bash
snmpwalk -v2c -c public 10.10.10.92 hrSWRunName
snmpwalk -v2c -c public 10.10.10.92 hrSWRunName | grep python
snmpwalk -v2c -c public 10.10.10.92 hrSWRunTable | grep "568"
```

Aqui vemos credenciales `loki:godofmischiefisloki`. Si nos connectamos con estas credenciales en el puerto 3366, podemos entrar
y vemos una tabla con otras credenciales. Vamos a la pagina del ipv6 y intentamos credenciales.

```bash
loki:godofmischiefisloki
loki:trickeryyanddeceit
admin:godofmischiefisloki
admin:trickeryyanddeceit
administrator:godofmischiefisloki
administrator:trickeryyanddeceit
```

vemos con la ultima credencial nos podemos connectar. Vemos un panel de ejecucion de comandos.

