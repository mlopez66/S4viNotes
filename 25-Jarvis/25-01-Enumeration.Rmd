## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.143
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.143
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.143 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80,64999, 10.10.10.143 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?           |
| ------ | -------- | ------------------ | -------------------- |
| 22     | ssh      | Conneccion directa | usuario y contraseña |
| 80     | http     | Web, Fuzzing       |                      |
| 64999  | http     | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.143
```

Vemos un dominio `logger.htb` pero poco mas. Añadimo el dominio a nuestro `/etc/hosts`

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.143 -oN webScan
```

Vemos que hay un `/phpmyadmin`

#### Analyzando la web con Firefox {-}

Es una web de un hotel donde se puede hacer reservaciones. Cuando miramos mas en profundidad, nos damos cuenta de algo que nos 
llama la atencion `http://10.10.10.143/room.php?cod=6`

Si cambiamos el **cod** con numeros invalidos vemos que intenta mostrarnos algo sin mensajes de error. Vamos a comprobar si esta
vulnerable a injeccion SQL