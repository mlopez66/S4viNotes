## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.13
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.13
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.13 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,53,80 10.10.10.13 -oN targeted
```


| Puerto | Servicio | Que se nos occure?                     | Que falta?            |
| ------ | -------- | -------------------------------------- | --------------------- |
| 22     | ssh      | Conneccion directa                     | usuario y contraseña  |
| 53     | Domain   | AXFR - Ataque de transferencia de zona | Conocer algun dominio |
| 80     | http     | Web, Fuzzing                           |                       |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.13
```

Nada interesante aqui

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.143 -oN webScan
```

Vemos que hay un `/phpmyadmin`

#### Analyzando la web con Firefox {-}

Es la pagina Apache2 por defecto

### Analyzando los dominios {-}

Como el puerto 53 esta abierto vamos a ver si podemos recuperar dominios con **nslookup**

```bash
nslookup

>server 10.10.10.13
>10.10.10.13
13.10.10.10.in-addr.arpa    name = ns1.cronos.htb
```

Vemos un dominio `cronos.htb` y lo añadimos a nuestro `/etc/hosts`

Si lanzamos Firefox con la url `http://cronos.htb` vemos una pagina differente de la pagina apache2 por defecto, lo que
significa que estamos en frente de un **virtualhost**

Vamos a intentar hacer ataques de transferencia de zona
