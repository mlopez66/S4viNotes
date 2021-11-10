## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.100
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.100
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.100 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,88,135,139,289,445,464,593,636,3269,5985,9389,49667,49673,49674,49677,49689,49698 10.10.10.100 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
| 88     | Kerberos   | asproasting attack                       | lista de usuarios validos |
| 135    | msrpc      |                                          |                           |
| 139    | netbios    |                                          |                           |
| 389    | LDAP       | Bloodhound                               | credenciales              |
| 445    | smb        | Null session                             |                           |
| 464    | kpasswd5?  |                                          |                           |
| 593    | ncacn_http |                                          |                           |
| 636    | tcpwrapped |                                          |                           |
| 3268   | ldap       |                                          |                           |
| 3269   | tcpwrapped |                                          |                           |
| 5722   | WinRM      | evil-winrm                               | credenciales              |
| 9389   | mc-nmf     | Puertos por defecto de windows           |                           |
| 47001  | msrpc      | Puertos por defecto de windows           |                           |
| 49152  | msrpc      | Puertos por defecto de windows           |                           |
| 49153  | msrpc      | Puertos por defecto de windows           |                           |
| 49154  | msrpc      | Puertos por defecto de windows           |                           |
| 49155  | ncacn_http | Puertos por defecto de windows           |                           |
| 49157  | msrpc      | Puertos por defecto de windows           |                           |
| 49158  | msrpc      | Puertos por defecto de windows           |                           |
| 49169  | msrpc      | Puertos por defecto de windows           |                           |
| 49171  | msrpc      | Puertos por defecto de windows           |                           |
| 49182  | msrpc      | Puertos por defecto de windows           |                           |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.100
smbclient -L 10.10.10.100 -N
smbmap -H 10.10.10.100 -u 'null'
```

Vemos que estamos frente de una maquina Windows 6.1 x64 que se llama **DC** en el dominio **active.htb** con un certificado firmado.
Añadimos el dominio al `/etc/hosts`.
Tambien vemos que podemos ver los recursos compartidos a nivel de red con un null session y que el recurso **Replication** esta en **READ ONLY**.
Listamos el directorio con **smbmap**

```bash
smbmap -H 10.10.10.100 -r Replication
smbmap -H 10.10.10.100 -r Replication/active.htb
```

Aqui vemos

- DfsrPrivate
- Policies
- scripts

Esto nos hace pensar a una replica de **SYSVOL**. Aqui buscamos si esta el `groups.xml`

```bash
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}/MACHINE
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}/MACHINE/Preferences
smbmap -H 10.10.10.100 -r Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04F894F9}/MACHINE/Preferences/Groups/*
```

