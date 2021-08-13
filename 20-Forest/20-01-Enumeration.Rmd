## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.161
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.161
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.161 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49684,49703,49918 10.10.10.161 -oN targeted
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
| 5985   | WinRM      | evil-winrm                               | credenciales              |
| 9389   | mc-nmf     | Puertos por defecto de windows           |                           |
| 47001  | http       | Puertos por defecto de windows           |                           |
| 49664  | msrpc      | Puertos por defecto de windows           |                           |
| 49665  | msrpc      | Puertos por defecto de windows           |                           |
| 49666  | msrpc      | Puertos por defecto de windows           |                           |
| 49667  | msrpc      | Puertos por defecto de windows           |                           |
| 49671  | msrpc      | Puertos por defecto de windows           |                           |
| 49676  | ncacn_http | Puertos por defecto de windows           |                           |
| 49677  | msrpc      | Puertos por defecto de windows           |                           |
| 49684  | msrpc      | Puertos por defecto de windows           |                           |
| 49703  | msrpc      | Puertos por defecto de windows           |                           |
| 49918  | msrpc      | Puertos por defecto de windows           |                           |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.161
smbclient -L 10.10.10.82 -N
```

Vemos que estamos en frente de una maquina Windows Server 2016 Standard de 64 bit pro que se llama **FOREST** en el dominio **htb.local**.
No vemos ningun recursos compartidos a nivel de red.
Añadimos el dominio a nuestro `/etc/hosts`.

### Buscando ususarios con rpcclient y rpcenum {-}

```bash
rpcclient -U "" 10.10.10.161 -N

rpcclient $> enumdomusers
```

Como nos deja connectarnos con el null session vamos a enumerar esto con la utilidad rpcenum de s4vitar

```bash
git clone https://github.com/s4vitar/rpcenum
cd rpcenum
./rpcenum -e All -i 10.10.10.161
```

Como aqui ya tenemos un listado de usuarios validos, lanzamos un ataque asproarst.

