## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.63
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.63
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.63 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,135,445,50000 10.10.10.63 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 80     | http     | Web, Fuzzing       |            |
| 135    | msrpc    |                    |            |
| 445    | smb      | Null session       |            |
| 50000  | http     | Web, Fuzzing       |            |

### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.63
smbclient -L 10.10.10.63 -N
smbmap -H 10.10.10.63 -u 'null'
```

Solo hemos podido comprobar que estamos frente a una maquina windows 10 pero poco mas.

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.63
```

Estamos en frente de un IIS

#### Analyzando la web con Firefox {-}

Vemos una pagina de busqueda typo Google.

Buscando en internet vemos una routa potencial que seria `/askjeeves/` pero no nos da en este caso

Intentamos ver lo que hay en el puerto **50000** y tenemos un 404. Si le ponemos el `/askjeeves/`, llegamos en 
un panel de administration de Jenkins.



