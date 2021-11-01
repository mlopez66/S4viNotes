## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.162
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.162
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.162 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80,443 10.10.10.162 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | tcp      | Conneccion directa | creds      |
| 80     | http     | Web, Fuzzing       |            |
| 443    | https    | Web, Fuzzing       |            |


El scaneo de nmap nos muestra 2 dominios 

- mango.htb
- staging-order.mango.htb

los añadimos al `/etc/hosts`

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.162
whatweb https://10.10.10.162
```

Es un Apache 2.4.29 en un Ubuntu. El puerto 80 nos muestra un 403 Forbiden pero no el 443.

#### Checkeamos el certificado ssl {-}

```bash
openssl s_client -connect 10.10.10.162:443
```

Nuevamente vemos el dominio `staging-order.mango.htb`

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.162`, Vemos que no tenemos acceso. Si vamos con **https**, vemos una web stylo Google.
Ocure lo mismos con el dominio `mango.htb` pero con el dominio `staging-order.maquina.htb` por **http**, vemos un panel de inicio de 
session.

Aqui probamos cosas uzando el burpsuite.

```bash
username=admin&password=admin&login=login
username=admin'&password=admin&login=login
username=admin'&password=admin'&login=login
username=admin' or 1=1-- -&password=admin&login=login
username=admin' and sleep(5)-- -&password=admin&login=login
username=admin' and sleep(5)#&password=admin&login=login
username=admin' or sleep(5)#&password=admin&login=login
username=admin or sleep(5)#&password=admin&login=login
username=admin and sleep(5)#&password=admin&login=login
```

No parece ser vulnerable a SQLI.
