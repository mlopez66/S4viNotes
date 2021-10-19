## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.220
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.220
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.220 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,5080 10.10.10.220 -oN targeted
```


| Puerto | Servicio      | Que se nos occure? | Que falta?           |
| ------ | ------------- | ------------------ | -------------------- |
| 22     | ssh           | Conneccion directa | usuario y contraseña |
| 5080   | http          | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.220
```

Es un nginx con gitlab y nos reporta un redirect al http://10.10.10.220/users/sign_in 

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.220:5080` nos redirige automaticamente a la pagina de Sign in de gitlab Community edition.
Siendo un gitlab podemos ver el `robots.txt`.

Vemos routas que pueden ser interesantes como

- /api


En el caso de la routa `/api` si tiramos de esta routa con firefox, vemos que necessitamos logearnos para continuar. Pero en ciertos casos,
hay possibilidades de poder, de forma no authenticada, obtener informaciones relevantes.

Si buscamos en google por `gitlab api`, vemos de que manera podemos utilizar la api para recoger informaciones.

```bash
curl -s -X GET "http://10.10.10.220:5080/api/v4/version"
```

Aqui vemos que necessitamos un token y para esto tenemos que crearnos un usuario. Lo hacemos desde la web. Una vez hecho nos podemos loggear
y desde la interface de gitlab, si vamos a Settings, nos podemos crear un token. Lo copiamos y lo añadimos a un header con curl.

```bash
curl -s -X GET "http://10.10.10.220:5080/api/v4/version" -H "PRIVATE-TOKEN: 514gTTxhx3qpsBbJbfz9" | jq
```

Aqui vemos que la version de gitlab es la 11.4.7


