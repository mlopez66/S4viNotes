## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.198
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.198
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.198 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p8080,7680 10.10.10.198 -oN targeted
```

| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 7680   | http     | Web, fuzzing       |            |
| 8080   | http     | Web, fuzzing       |            |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.198:8080
```

Nada muy interressante aqui


#### Checkear la web el puerto 8080 {-}

- Vemos que hay un panel de inicio de session
- El Wappalizer no nos dice nada
- Hay unos cuantos links
    
    1. Packages
    1. Facilities
    1. About
    1. Contact

- En packages vemos un usuario potencial **mrb3n**
- Vemos que las extensiones de los ficheros son php
- Si pinchamos en Contact vemos que la web a sido echa con **Gym Management Software 1.0**

Vamos a ver si encontramos algo interressante con Gym Management Software 1.0

