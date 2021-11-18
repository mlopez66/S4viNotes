## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.37
```
ttl: 63 -> maquina linux. 
Recuerda que en cuanto a ttl se trata, 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.37 
```

si consideras que va muy lento el escaneo puedes poner los siguientes parametros para que valla mucho mas rapido

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.37 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,22,80,25565 10.10.10.37 -oN targeted
```

| Puerto | Servicio  | Que se nos occure?                        | Que falta?           |
| ------ | --------- | ----------------------------------------- | -------------------- |
| 21     | ftp       | conectar como anonymous                   |                      |
| 22     | ssh       | conexion directa                          | usuario y contraseña |
| 80     | http      | Analisis de la web y Fuzzing              |                      |
| 25565  | minecraft | con el puerto 53 pensamos en virt hosting |                      |


### Conectar al ftp como anonymous {-}

```bash
ftp 10.10.10.37
Name: anonymous
password: <enter>
#Output
530 Login incorrect.
```

No nos deja entrar como anonymous

### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.37
```

Aqui vemos que estamos en un Wordpress

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.37 -oN webScan
```

Ya nos detecta un `/phpmyadmin/` y ficheros de wordpress

#### Chequear la web del puerto 80 {-}

Con firefox navegamos en la web para ver lo que es.

- wappalizer nos dice que es Wordpress
- Vemos que la web esta under construction
- Si pinchamos el post vemos que es el usuario NOTCH que lo a echo

Como es un wordpress intentamos ir al `http://10.10.10.37/wp-login.php` y miramos si hay el usuario NOTCH. 
Efectivamente el usuario NOTCH existe. 

Vamos a por el `http://10.10.10.37/phpmyadmin/` y buscamos previamente en google si encontramos credenciales por
defecto pero no funcionan.

Tenemos que ir buscando mas rutas.

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.37/WFUZZ
```

Encontramos un ruta plugins que no suele ser normal porque en wordpress los plugins suelen estar en `/wp-content/plugins` y no
en `/plugins` directamente

Aqui encontramos dos ficheros `.jar`. Los descargamos en nuestra maquina de atacante.




