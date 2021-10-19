## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.209
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.209
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.209 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80,8089 10.10.10.209 -oN targeted
```


| Puerto | Servicio      | Que se nos occure? | Que falta?           |
| ------ | ------------- | ------------------ | -------------------- |
| 22     | ssh           | Conneccion directa | usuario y contraseña |
| 80     | http          | Web, Fuzzing       |                      |
| 8089   | https splunkd | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.209
```

Es un Apache 2.4.41 en un Ubuntu. Vemos un email `info@doctors.htb` Podria ser un usuario y un dominio. Añadimos el dominio al `/etc/hosts`

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.209`, vemos una pagina de un cabinete de doctor. Navigamos un poco en la web pero no hay nada interesante.
Si entramos en la web por el dominio `http://doctors.htb` vemos una nueva pagina. Se esta aplicando virtual hosting. Esta pagina es un login.
El wappalizer nos dice que es un Flask en python.

Aqui de seguida pensamos en un **Template Injection**.

De primeras creamos un nuevo usuario en el panel de registro. 
Vemos que nuestra cuenta a sido creada con un limite de tiempo de 20 minutos. Nos loggeamos y vemos un boton con un numero 1.
Si pinchamos, vemos en la url `http://doctors.htb/home?page=1`. Miramos si se puede aplicar un LFI

```bash
http://doctors.htb/home/page=/etc/passwd
http://doctors.htb/home/page=../../../../../../../../etc/passwd
http://doctors.htb/home/page=../../../../../../../../etc/passwd%00
http://doctors.htb/home/page=../../../../../../../../etc/passwd?
```

Aqui no vemos nada.

Hay un link en la pagina para redactar un nuevo mensaje.

```bash
Title: EEEEEEEEE
Content: Hola
```

Aqui vemos que el mensaje esta visible en la pagina.

> [ ! ] NOTAS: Tito nos habla de probar un RFI (Remote File Inclusion) que seria algo que probar pero nos adelanta que no funcciona en este caso.

Aqui miramos de Injectar etiquetas HTML y XSS pero no funcciona.
