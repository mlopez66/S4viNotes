## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.197
```
ttl: 63 -> maquina linux. 
Recuerda que tratandose de ttl 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.197 
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.197 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,22,25,80,143,993,8080 10.10.10.197 -oX targetedXML
```


|Puerto|Servicio    | Que se nos occure?                  |    Que falta?      |
|------|------------|-------------------------------------|--------------------|
|21    |ftp         |Conexion como Anonymous              |                    |
|22    |ssh         |Accesso directo                      |usuario y contraseña|
|25    |smtp        |Por detras hay algo rel. email       |                    |
|80    |http        |Redirect to sneakycorp.htb hosts     |                    |
|143   |IMAP        |Connectar para listar contenido mail |usuario y contraseña|
|993   |squid-proxy |Browsear la web por este puerot      |Checkear el exploit |
|8080  |http        |Browsear la web por este puerto      |Checkear la web     |


#### FTP {-}

Intentamos conectarnos como anonymous.

```bash
ftp 10.10.10.197
> Name : anonymous
```

#### Whatweb {-}

```bash
whatweb http://10.10.10.197
```

Hay un redirect a `sneakycorp.htb`

#### Add sneakycorp.htb host {-}

```bash
nano /etc/hosts
```

```{r, echo = FALSE, fig.cap="hosts sneakycorp.htb", out.width="90%"}
    knitr::include_graphics("images/hosts-sneakycorp.png")
```

#### Checkear la web del puerto 8080 {-}

Abrimos la web y vemos cosas:

- Ya estamos logeados
- Hay mensajes de collegasos, pinchamos pero no passa nada
- Proyecto pypi testeado a 80%
- Proyecto POP3 y SMTP testeado completamente
- Es possible installar modulos con pip en el servidor
- Hay un enlace a Team y vemos una lista de emails


#### Recuperar la lista de email con CURL {-}

```bash
curl -s -X GET "http://sneakycorp.htb/team.php" | html2text | grep "@" | awk 'NF{print $NF}' > email.txt
```

