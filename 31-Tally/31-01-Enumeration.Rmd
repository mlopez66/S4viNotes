## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.59
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.59
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.59 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,80,81,135,139,445,808,1433,5985,15567,32843,32844,32846,47001,49664,49665,49666,49667,49668,49669,49670 10.10.10.59 -oN targeted
```


| Puerto | Servicio      | Que se nos occure?             | Que falta?   |
| ------ | ------------- | ------------------------------ | ------------ |
| 21     | ftp           | Conexion como Anonymous        |              |
| 80     | http          | Web, Fuzzing                   |              |
| 81     | http          | Web, Fuzzing                   |              |
| 135    | msrpc         |                                |              |
| 139    | netbios       |                                |              |
| 445    | smb           | Null session                   |              |
| 808    | ccproxy-http? |                                |              |
| 1433   | ms-sql-s      |                                |              |
| 5985   | WinRM         | evil-winrm                     | credenciales |
| 15567  | http          | Web, Fuzzing                   |              |
| 32843  | mc-nmf        | Puertos por defecto de windows |              |
| 32844  | mc-nmf        | Puertos por defecto de windows |              |
| 32846  | mc-nmf        | Puertos por defecto de windows |              |
| 47001  | http          | Puertos por defecto de windows |              |
| 49664  | msrpc         | Puertos por defecto de windows |              |
| 49665  | msrpc         | Puertos por defecto de windows |              |
| 49666  | msrpc         | Puertos por defecto de windows |              |
| 49667  | msrpc         | Puertos por defecto de windows |              |
| 49668  | msrpc         | Puertos por defecto de windows |              |
| 49669  | msrpc         | Puertos por defecto de windows |              |
| 49670  | msrpc         | Puertos por defecto de windows |              |

### Conexion Anonymous con ftp {-}

```bash
ftp 10.10.10.59

Name: anonymous
Password: 

User cannot login
```

El usuario anonymous no esta habilitado.

### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.59
smbclient -L 10.10.10.59 -N
```

Vemos que estamos en frente de una maquina Windows Server 2016 Standard de 64 bit pro que se llama **TALLY** en el dominio **TALLY**.
No podemos connectarnos con un NULL Session.

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.59
```

Nos enfrentamos a un Microsoft Sharepoint con un IIS 10.0


#### Analyzando la web con Firefox {-}

Entramos en un panel Sharepoint y vemos en la url que hay un `_layouts`

Buscamos en google por la palabra `sharepoint pentest report` y encontramos la web de [pentest-tool](https://pentest-tools.com/public/sample-reports/sharepoint-scan-sample-report.pdf). Esto



