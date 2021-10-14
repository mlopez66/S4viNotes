## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.93
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.93
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.93 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80 10.10.10.93 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 80     | http     | Web, Fuzzing       |            |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.93
```

Estamos en frente de un IIS

#### Analyzando la web con Firefox {-}

Vemos una imagen de Merlin ;)

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.93/FUZZ
```

Encontramos una routa `uploadedFiles`, probamos con una extension `.aspx` porque es un IIS

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.93/FUZZ.aspx
```

Encontramos una routa `transfer.aspx`

Si la analyzamos con firefox, vemos una pagina que nos permite subir ficheros.
