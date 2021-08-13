## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.82
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.82
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.82 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,135,139,445,1521,5985,47001,49152,49153,49154,49155,49159,49160,49161,49162 10.10.10.82 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?             | Que falta? |
| ------ | ---------- | ------------------------------ | ---------- |
| 80     | http       | Web, fuzzing                   |            |
| 135    | msrpc      |                                |            |
| 139    | netbios    |                                |            |
| 445    | smb        | Null session                   |            |
| 1521   | oracle-tns | Attacke con ODAT               |            |
| 5985   | msrpc      | Puertos por defecto de windows |            |
| 47001  | msrpc      | Puertos por defecto de windows |            |
| 49152  | msrpc      | Puertos por defecto de windows |            |
| 49153  | msrpc      | Puertos por defecto de windows |            |
| 49154  | msrpc      | Puertos por defecto de windows |            |
| 49155  | msrpc      | Puertos por defecto de windows |            |
| 49159  | msrpc      | Puertos por defecto de windows |            |
| 49160  | msrpc      | Puertos por defecto de windows |            |
| 49161  | msrpc      | Puertos por defecto de windows |            |
| 49162  | msrpc      | Puertos por defecto de windows |            |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.82
smbclient -L 10.10.10.82 -N
```

Vemos que estamos en frente de una maquina Windows Server 2021 R2 de 64 bit pro que se llama **SILO** en el dominio **SILO** y poco mas

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.82
```

Nada muy interressante aqui


#### Checkear la web {-}

Sabemos que es un IIS 8.5 y asp.net pero poco mas. Vamos a fuzzear routas.


