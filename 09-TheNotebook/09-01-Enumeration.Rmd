## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.230
```
ttl: 63 -> maquina linux.
Recuerda que en cuanto a ttl respecta 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.230 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.230 -oN targeted
```

| Puerto | Servicio  | Que se nos occure?                        | Que falta?           |
| ------ | --------- | ----------------------------------------- | -------------------- |
| 22     | ssh       | conexion directa                        | usuario y contraseña |
| 80     | http      | Analizis de la web y Fuzzing              |                      |


### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.230
```

Nada muy interesante

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.230 -oN webScan
```

Ya nos detecta un `/phpmyadmin/` y ficheros de wordpress

#### Chequear la web por puerto 80 {-}

Con firefox navigamos en la web para ver lo que es.

- wappalizer nos dice que hay nginx ubuntu bootstrap
- hay un register y un login pero no vemos extensiones php
- Si pinchamos el login intentamos ponerle un admin admin y nos dice que la contraseña es incorrecta -> usuario admin existe
- Si ponemos administrator admin nos dice que el usuario es incorrecto

Vemos que hay formas de enumeracion con este login



#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.37/WFUZZ
```

Encontramos un ruta plugins que no suele ser normal porque en wordpress los plugins suelen estar en `/wp-content/plugins` y no
en `/plugins` directamente

Aqui encontramos dos ficheros `.jar`. Los descargamos en nuestra maquina de atacante.




