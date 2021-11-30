## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.91
```
ttl: 63 -> maquina Linux. 
Recordar que en cuanto a ttl se trata 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.91 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,5000 10.10.10.91 -oN targeted
```

| Puerto | Servicio | Que se nos occure? | Que falta?   |
| ------ | -------- | ------------------ | ------------ |
| 22     | ssh      | Acceso directorio  | Credenciales |
| 5000   | http     | Web, fuzzing       |              |


### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.91:5000
```

Nada muy interesante

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p5000 10.10.10.91 -oN webScan
```

No nos detecta nada

#### Chequear la web por puerto 5000 {-}

Con firefox navegamos en la web para ver lo que es. 

- Under construction
- la web es una simple imagen
- hablan de `.py`
- vemos usuarios

Como no hay nada interesante vamos a por WFUZZ

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.91:5000/FUZZ
```

Encontramos una ruta `/feed` y `/upload`. Lo chequeamos en firefox. 

#### Chequeamos la ruta upload {-}

Vemos una pagina que nos permite uploadear ficheros. Parece que tenemos que uploadear ficheros XML que tiene que tener los elementos
siguientes:

- Author
- Subject
- Content

Huele a **XXE** pero primero tratamos de ver si podemos uploadear ficheros de otro tipo.

creamos ficheros

1. fichero **txt**

    ```bash
    vi test.txt

    EEEEEEE
    ```

1. fichero **php**

    ```php
    vi test.php

    <?php
        echo "EEEEEEEEEEE";
    ?>
    ```

Cuando los uploadeamos no se ve nada. No sabemos si la web nos subio los archivos o no. Intentamos con un fichero XML

```xml
vi test.xml

<elements>
    <Author>S4vitar</Author>
    <Subject>EEEEEEEEE</Subject>
    <Content>EEEAEAEAAAEAAEAE</Content>
</elements>
```

Lo uploadeamos y ahora vemos que el Blogpost a sido processado, vemos los elementos **Author** **Subject** **Content** y que lo a guardado en
`/home/roosa/deploy/src` y que la url para **later reference** es `/uploads/test.xml`

Si miramos lo que hay en `http://10.10.10.91:5000/upload/test.xml` vemos el contenido de nuestro fichero XML




