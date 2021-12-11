## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Conexion desde la vulnerabilidad de Voting System {-}

1. Controlamos que las urls que estan en el script existen en la web.

    Aqui vemos que las urls no son exactamente las mismas y que hay que modificarlas un poquito.

1. Modificamos el script para que ataque el servicio de la maquina victima

    ```{r, echo = FALSE, fig.cap="voting system reverse shell", out.width="90%"}
    knitr::include_graphics("images/love-votingsystem-rshell.png")
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Lanzamos el script.

    ```bash
    python3 voting-system.py
    ```

Ya estamos en la maquina.