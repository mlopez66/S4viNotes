## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.175
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.175
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.175 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,80,88,135,139,289,445,464,593,636,3269,5985,9389,49667,49673,49674,49677,49689,49698 10.10.10.175 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
| 80     | http       | WebFuzzin                                |                           |
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
| 49667  | msrpc      | Puertos por defecto de windows           |                           |
| 49673  | msrpc      | Puertos por defecto de windows           |                           |
| 49673  | msrpc      | Puertos por defecto de windows           |                           |
| 49674  | ncacn_http | Puertos por defecto de windows           |                           |
| 49677  | msrpc      | Puertos por defecto de windows           |                           |
| 49689  | msrpc      | Puertos por defecto de windows           |                           |
| 49698  | msrpc      | Puertos por defecto de windows           |                           |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.175
smbclient -L 10.10.10.175 -N
smbmap -H 10.10.10.175 -u 'null'
```

Vemos que estamos frente de una maquina Windows 10 que se llama **SAUNA** en el dominio **EGOTISTICAL-BANK.LOCAL** con un certificado firmado.
Añadimos el dominio al `/etc/hosts`.
Tambien vemos que no podemos ver los recursos compartidos a nivel de red con un null session.

### Buscando ususarios con rpcclient y rpcenum {-}

```bash
rpcclient -U "" 10.10.10.175 -N

rpcclient $> enumdomusers
```

Podemos conectar pero no nos deja ver usuarios del directorio activo.


### Kerbrute {-}

```bash
git clone https://github.com/ropnop/kerbrute
cd kerbrute
go build -ldflags "-s -w" .
upx kerbrute
./kerbrute userenum --dc 10.10.10.175 -d egotistical-bank.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.175
```

Es un IIS 10.0

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.175`, Vemos una pagina Egotistical Bank. Navegando por el `about.html` vemos usuarios potenciales. Vamos a recuperarlos
con bash

```bash
curl -s -X GET "http://10.10.10.175/about.html"
curl -s -X GET "http://10.10.10.175/about.html" | grep "p class=\"mt-2"
curl -s -X GET "http://10.10.10.175/about.html" | grep "p class=\"mt-2" | grep "Fergus Smith" -A 100 | html2text > users
```

Modificamos el fichero users para crear nombres de usuarios como `fsmith`,`f.smith`,`frank.smith`, `smithf`, `smith.frank` o otros y intentamos un asproasting attack.
