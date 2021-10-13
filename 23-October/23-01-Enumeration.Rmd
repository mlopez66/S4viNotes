## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.16
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.16
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.16 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.16 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?           |
| ------ | -------- | ------------------ | -------------------- |
| 22     | ssh      | Conneccion directa | usuario y contraseña |
| 80     | http     | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.16
```

Vemos que estamos en frente de una maquina Linux servido por un Apache 2.4.7 con un php 5.5.9-1.
Vemos que estamos en frente de un October CMS - Vanilla.

#### Checkear la web del puerto 80 {-}

Con firefox navigamos en la web para ver lo que es. El Wappalyzer nos confirma que estamos contra un October CMS y Laravel.
Como es un gestor de contenido buscamos en google la routa del admin panel y vemos que esta en `/backend`.

