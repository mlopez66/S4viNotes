## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.103
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.103
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.103 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,53,80,135,139,389,443,445,464,593,636,3268,3269,5985,5986,9389,47001,49664,49665,49666,49667,49668,49677,49688,49689,49691,49694,49706,49712,49720 10.10.10.103 -oN targeted
```


| Puerto | Servicio   | Que se nos occure?                          | Que falta?     |
| ------ | ---------- | ------------------------------------------- | -------------- |
| 21     | ftp        | Anonymous connection                        |                |
| 53     | domain     | Domain Controller ataque transferencia zona | dominio valido |
| 80     | http       | web Fuzzin                                  |                |
| 135    | msrpc      |                                             |                |
| 139    | netbios    |                                             |                |
| 389    | LDAP       | Bloodhound ldapdomaindump                   | credenciales   |
| 443    | https      | web Fuzzin                                  |                |
| 445    | smb        | Null session                                |                |
| 464    | kpasswd5?  |                                             |                |
| 593    | ncacn_http |                                             |                |
| 636    | tcpwrapped |                                             |                |
| 3268   | ldap       |                                             |                |
| 3269   | tcpwrapped |                                             |                |
| 5985   | WinRM      | evil-winrm                                  | credenciales   |
| 5986   | WinRM ssl  | evil-winrm                                  | credenciales   |
| 9389   | mc-nmf     | Puertos por defecto de windows              |                |
| 47001  | http       | Puertos por defecto de windows              |                |
| 49664  | msrpc      | Puertos por defecto de windows              |                |
| 49665  | msrpc      | Puertos por defecto de windows              |                |
| 49666  | msrpc      | Puertos por defecto de windows              |                |
| 49668  | msrpc      | Puertos por defecto de windows              |                |
| 49677  | msrpc      | Puertos por defecto de windows              |                |
| 49688  | ncacn_http | Puertos por defecto de windows              |                |
| 49689  | msrpc      | Puertos por defecto de windows              |                |
| 49691  | msrpc      | Puertos por defecto de windows              |                |
| 49694  | msrpc      | Puertos por defecto de windows              |                |
| 49706  | msrpc      | Puertos por defecto de windows              |                |
| 49712  | msrpc      | Puertos por defecto de windows              |                |
| 49720  | msrpc      | Puertos por defecto de windows              |                |


### Analyzando el FTP {-}

```bash
ftp 10.10.10.103
Name: anonymous
Password: #Enter
#Output
User logged in.
dir
ls -la
```

Hemos podido loggearnos como el usuario **anonymous** pero no vemos nada. Miramos si podemos subir archivos.

```bash
echo "content" > prueba.txt

ftp 10.10.10.103
Name: anonymous
Password: #Enter
#Output
User logged in.

put prueba.txt
#Output
550 Access is denied.
```

No podemos subir archivos.

### Analysis del certificado ssl {-}

```bash
openssl s_client -connect 10.10.10.103:443
```

Aqui vemos el dominio `sizzle.htb.local` y lo metemos en el `/etc/hosts`

### Analysis del dominio {-}

```bash
dig @10.10.10.103 sizzle.htb.local ns
```

Encontramos otro dominio, el `hostmaster.htb.local` que añadimos en el `/etc/hosts`. Miramos si es vulnerable a ataque de transferencia de zona.

```bash
dig @10.10.10.103 sizzle.htb.local axfr
```

Aqui vemos que no applica.

### Analysis del RPC {-}

```bash
rpcclient -U "" 10.10.10.103 -N

rpcclient $> enumdomusers
#Output
NT_STATUS_ACCESS_DENIED
```

Aqui vemos que hemos podido connectar con el NULL Session pero no tenemos derecho de enumerar usuarios a nivel de dominio.

### Analyzando el SMB {-}

```bash
crackmapexec smb 10.10.10.103
smbmap -H 10.10.10.103 -u 'null'
```

Vemos que estamos en frente de una maquina Windows 10 de 64 bit pro que se llama **SIZZLE** en el dominio **htb.local**.
Vemos que hay recursos compartidos a nivel de red con los recursos `IPC$` y `Department Shares` con derechos de lectura.
Seguimos analyzando con **smbclient**

```bash
smbclient "//10.10.10.103/Department Shares" 10.10.10.103 -N
smb: \>

dir
```

Aqui vemos muchos directorios y es bastante dificil ver todo lo que hay desde smbclient. Nos creamos una montura para visualizar este recurso.

```bash
mkdir /mnt/smb
mount -t cifs "//10.10.10.103/Department Shares" /mnt/smb
cd /mnt/smb
tree
cd Users
```
