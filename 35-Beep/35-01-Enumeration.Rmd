## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.7
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.7
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.7 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,25,80,110,111,143,443,878,993,995,3306,4190,4445,4559,5038,10000, 10.10.10.7 -oN targeted
```


| Puerto | Servicio      | Que se nos occure? | Que falta?           |
| ------ | ------------- | ------------------ | -------------------- |
| 22     | ssh           | Conneccion directa | usuario y contraseña |
| 25     | ssh           | Conneccion directa | usuario y contraseña |
| 80     | http          | Web, Fuzzing       |                      |
| 110    | pop3          |                    |                      |
| 111    | rpcbind       |                    |                      |
| 143    | imap          |                    |                      |
| 443    | https         | Web, Fuzzing       |                      |
| 878    | rpc           |                    |                      |
| 993    | ssl/imap      |                    |                      |
| 995    | pop3          |                    |                      |
| 3306   | mysql         |                    |                      |
| 4190   | sieve cyrus   |                    |                      |
| 4445   | upnotifyp     |                    |                      |
| 4559   | HylaFAX       |                    |                      |
| 5038   | asterisk      |                    |                      |
| 10000  | http miniserv |                    |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.7
```

Es un Apache 2.2.3 sobre un CentOS y habla de redirection sobre el protocolo https.

#### Checkear la web {-}

Cuando nos connectamos por el puerto 80, se ve la redirection al puerto 443 y entramos directo
en un panel de authentificacion `elastix`.

Si miramos el miniserv del puerto **10000** tambien vemos un panel de login.

En este caso buscamos por una vulnerabilidad associada a `elastix`
