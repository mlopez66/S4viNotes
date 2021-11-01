## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root/
id
sudo -l
ls -l
```

No tenemos privilegios claramente definida pero un fichero no llama la atencion. Este fichero que es un `RemoteConnection.exe`, un fichero
windows en una maquina Linux.

Nos descargamos el fichero uzando un base64

1. En la maquina victima

    ```bash
    base64 -w 0 `RemoteConnection.exe ; echo
    ```

1. Copiamos el hash y lo colamos en la maquina de atacante 

    ```bash
    bash
    echo "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..." base64 -d > RemoteConnection.exe
    ```

1. Controlamos los ficheros con md5sum y transferimos el RemoteConnection.exe a una maquina Windos que tiene el Immunity Debugger con el DEP desabilitado.
1. Lanzando el programa en la maquina Windows, vemos que nos falta una .dll, la descargamos de internet y la ponemos en la routa `C:\Windows\System32`


Ya podemos lanzar el **Immunity Debugger** como administrador

1. Abrimos el RemoteConnection.exe desde el Immunity Debugger
1. En la ventana de arriba a la izquierda, hacemos un clic derecho > Search for > AllReferenced text strings

    vemos que hay un putty que sirbe de connection a una maquina linux desde windows.

1. Encontramos una string "clave", le damos al clic derecho > Follow in Disassembler

    Aqui vemos que hay un CMP que es un compare 

1. Justo antes de esta comparativa ponemos un breakpoint para ver con que se compara exactamente
1. Le damos al boton play

En la ventana de arriba a la derecha, podemos ver los datos que se utilizan para la coneccion con el SSH del usuario root.


```bash
ssh root@10.10.10.114
password: Qf7j8YSV.wDNF*[7d?j&eD4^
```

Ya estamos conectados como root y podemos leer la flag.
