## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.154
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.154
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.154 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,443,445,3306 10.10.10.154 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 80     | http     | Web Fuzzing        |            |
| 443    | https    | Web Fuzzing        |            |
| 445    | smb      | Null session       |            |
| 3306   | mysql    | Injeccion SQL      |            |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.154
smbclient -L 10.10.10.154 -N
smbmap -H 10.10.10.154 -u 'null'
```

Vemos que estamos en frente de una maquina Windows 10 Pro que se llama **BANKROBBER** en el dominio **Bankrobber** con un certificado no firmado.
Tambien vemos que no podemos ver los recursos compartidos a nivel de red con un null session.

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.154
whatweb https://10.10.10.154
```

Es un Apache 2.4.39 Win64 que usa openSSL y PHP 7.3.4 

#### Checkeamos el certificado ssl {-}

```bash
openssl s_client -connect 10.10.10.154:443
```

Aqui no vemos ningun dominio o cosa interesante.

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.154`, Vemos una pagina que habla de bitcoin y nos permite loggear o registrar. Empezamos por crear una cuenta
y nos loggeamos.

Aqui vemos que podemos transferir E-coin a alguien. Le ponemos

```bash
Amount: 1
ID of Addressee: 1
Comment to him/her: EEEEEEEEEE
```

Si transferimos, aparece una popup que nos dice que `Transfer on hold. An admin will review it within a minute.`




#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.34/FUZZ
```

Vemos un directorio `/jailuser` que lista un directorio `dev` que contiene ficheros. Nos descargamos estos ficheros.


