## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.155
```
ttl: 63 -> maquina linux. 
Recuerda que tratandose de ttl, 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.155 
```

Si consideras que va muy lento puedes meter los siguientes parametros para que valla mucho mas rapido

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.155 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p20,21,22,25,43,53,80 10.10.10.155 -oN targeted
```

| Puerto | Servicio | Que se nos occure?                                       | Que falta?           |
| ------ | -------- | -------------------------------------------------------- | -------------------- |
| 20     | ftp-data |                                                          |                      |
| 21     | ftp      | conectar como anonymous                                  |                      |
| 22     | ssh      | conexion directa                                         | usuario y contraseña |
| 25     | smtp     | email -> exim                                            | usuario y contraseña |
| 43     | whois    | SUPERSECHOSTING WHOIS (http://www.supersechosting.htb)   |                      |
| 53     | domain   | Domain zone transfer -> attacke de transferencia de zona |                      |
| 80     | http     | con el puerto 53 pensamos en virt hosting                |                      |


### Connectar al ftp como anonymous {-}

```bash
ftp 10.10.10.155
Name: anonymous
password: <enter>
#Output
530 Login incorrect.
```

No nos deja entrar como anonymous

### Analyzando la web {-}

#### Checkeamos la web port el ip {-}

Hablan de virtualhosting

```bash
nano /etc/hosts
```
```{r, echo = FALSE, fig.cap="hosts supersechosting", out.width="90%"}
    knitr::include_graphics("images/scavenger-hosts1.png")
```

Intentamos conectarnos otra vez a la web pero ahora con el url `http://supersechosting.htb` y tenemos el mismo resultado.






