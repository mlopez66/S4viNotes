## Vuln exploit & Gaining Access {-}

### Conneccion por ssh con id_rsa {-}

1. Copiamos el contenido de la id_rsa del pdf en un fichero id_rsa en nuestra maquina.
1. Le ponemos los derechos necesarios

    ```bash
    chmod 600 id_rsa
    ```

1. Nos connectamos

    ```bash
    ssh reader@10.10.10.176 -i id_rsa
    ```

Y ya estamos connectados como el usuario **reader** y podemos leer la flag.