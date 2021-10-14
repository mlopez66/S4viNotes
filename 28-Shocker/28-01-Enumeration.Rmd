## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.56
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.56
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.56 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,2222 10.10.10.56 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?           |
| ------ | -------- | ------------------ | -------------------- |
| 80     | http     | Web, Fuzzing       |                      |
| 2222   | ssh      | Conneccion directa | usuario y contraseña |




### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.56
```

Nada interesante aqui

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.56 -oN webScan
```

Nada interesante.

#### Analyzando la web con Firefox {-}

Hay una pagina que nos dice *Don't Bug Me!* y nada mas. Como la maquina se llama Shocker, pensamos directamente al ataque ShellShock

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.56/FUZZ/
```

Encontramos una routa muy interesante que es el `cgi-bin` que es la routa donde si la bash es vulnerable podemos hacer un ataque shellshock.

