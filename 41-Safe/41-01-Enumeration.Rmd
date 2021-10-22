## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.147
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.147
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.147 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80,1377 10.10.10.147 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | ssh      | Conneccion directa | creds      |
| 80     | http     | Web, Fuzzing       |            |
| 1337   | http     | Web, Fuzzing       |            |

El resultado de Nmap nos muestra algo raro con el puerto **1337**. Lo miramos con **ncat**

```bash
nc 10.10.10.247 1337

What do you want me to echo back?
AA

Ncat: Broken pipe
```

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.147
```

Es un Apache 2.4.25 en un Debian y parece que sea la default page de apache2. 


#### Checkear la web {-}

Si entramos en la url `http://10.10.10.147`, Vemos la pagina por por defecto de apache2.
Miramos el codigo fuente y vemos un commentario que dice `'myapp' can be dowloaded to analyse from here its running on port 1337`.

Si ponemos la url `http://10.10.10.147/myapp` podemos descargar la app y analyzarla.
