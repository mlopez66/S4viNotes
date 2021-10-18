## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.167
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.167
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.167 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,135,3306,49666,49667 10.10.10.167 -oN targeted
```


| Puerto | Servicio | Que se nos occure?   | Que falta? |
| ------ | -------- | -------------------- | ---------- |
| 80     | http     | Web, Fuzzing         |            |
| 135    | msrpc    |                      |            |
| 3306   | mysql    | SQLI                 |            |
| 49666  | msrpc    | puertos por defectos |            |
| 49667  | msrpc    | puertos por defectos |            |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.167
```

Nos enfrentamos a un Microsoft IIS 10.0 con PHP 7.3.7.

#### http-enum {-}

Lanzamos un web scan con nmap.

nmap --script http-enum -p80 10.10.10.167 -oN webScan

Nos detecta la routa `admin`

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.167/FUZZ
```

Encontramos las routas `uploads`, `admin`

### Analyzando la web con Firefox {-}

Entramos en una pagina, hay un boton admin en el menu y uno login.
Si miramos el codigo fuente vemos un comentario una Todo List:

- Import products
- Link to new payment system
- Enable SSL (Certificates location \\192.168.4.28\myfiles)

El ultimo en este caso es muy interesante.

Si pinchamos el link admin, vemos un mensaje **Acces Denied: Header Missing. Please ensure you go through the proxy to access this page**.
En este caso cuando se habla de proxy y de cabezera podemos uzar la heramienta **curl** con la cabezera **X-Forwarded-for**

### Cabezera proxy {-}

```bash
curl -s -X GET "http://10.10.10.167/admin.php" -H "X-Forwarded-For: 192.168.4.28"
```

Aqui vemos que nos a cargado una pagina.

```bash
curl -s -X GET "http://10.10.10.167/admin.php" -H "X-Forwarded-For: 192.168.4.28" | html2text
```

Como vemos informaciones interesantes, vamos a tirar de **burpsuite** para ver la informacion de manera normal.

### Añadir cabezera desde Burpsuite {-}

Una vez el burpsuite configurado con la maquina victima de target, vamos a añadir una cabezera. Lo podemos hacer de 2 maneras:

- Manual (cambiando de manera manual a cada peticion el header)
- Automatizada (que cada peticion use este header)

1. Pinchamos a Proxy > Options
1. Add Match and Replace

    ```{r, echo = FALSE, fig.cap="Azure DevOps repositories", out.width="90%"}
        knitr::include_graphics("images/Control-burp-xforwardingfor.png")
    ```

1. Interceptamos y vemos que se añade la cabezera
1. Desactivamos el intersepte 

Ya podemos navegar de manera normal.

Vemos una pagina con productos y un input para buscar productos. Si escribimos un producto, aparece una tabla con un titulo **id**.

Probamos poner un apostrofe `'` en el input de busqueda y nos sale un error SQL `Error SQLSTATE[42000] Syntax error or access violation You have an error in your SQL
syntax, check the manual that corresponds to your MariaDB server version for the right syntax to use near "'" at line 1`
