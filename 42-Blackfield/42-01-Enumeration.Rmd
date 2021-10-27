## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.192
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.192
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.192 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,88,135,139,389,445,593,3268,49676 10.10.10.192 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
| 88     | Kerberos   | asproasting attack                       | lista de usuarios validos |
| 135    | msrpc      |                                          |                           |
| 139    | netbios    |                                          |                           |
| 389    | LDAP       | Bloodhound                               | credenciales              |
| 445    | smb        | Null session                             |                           |
| 593    | ncacn_http |                                          |                           |
| 3268   | ldap       |                                          |                           |
| 5985   | WinRM      | evil-winrm                               | credenciales              |
| 49676  | ncacn_http | Puertos por defecto de windows           |                           |


### Buscando ususarios con rpcclient y rpcenum {-}

```bash
rpcclient -U "" 10.10.10.192 -N

rpcclient $> enumdomusers
```

Como no nos deja unumerar cosas con el null session vamos a necesitar credenciales validas para poder hacerlo

### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.192
smbclient -L 10.10.10.192 -N
```

Vemos que estamos en frente de una maquina Windows 10 Standard de 64 bit pro que se llama **DC01** en el dominio **BLACKFIELD.local**.
Añadimos los dominios `blackfield.local` y `dc01.blackfield.local` a nuestro `/etc/hosts`.

Tambien vemos recursos compartidos a nivel de red como:

- ADMIN$
- C$
- forensic
- IPC$
- NETLOGON
- profiles$
- SYSVOL

Usando de la heramienta smbmap, podemos ver si tenemos accessos a estos recursos.

```bash
smbmap -H 10.10.10.192 -u 'null'
```

y vemos que denemos accesso con derecho de lectura a los recursos `profiles$` y `IPC$`. IPC$ no es un recurso que nos interesa.

```bash
smbclient //10.10.10.192/profiles$ -N
dir
```

Aqui podemos ver registros que parecen ser directorios de ususarios.
