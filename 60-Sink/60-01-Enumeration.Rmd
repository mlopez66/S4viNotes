## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.225
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.225
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.225 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,3000,5000 10.10.10.225 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | ssh      | Coneccion directa  |            |
| 3000   | http     | Web Fuzzing        |            |
| 5000   | https    | Web Fuzzing        |            |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.225:3000
whatweb http://10.10.10.225:5000
```

Vemos en el puerto 3000 informacion que habla de un git un poco como un github. Y en el puerto 5000 vemos un password field que parece ser un
panel de inicio de session.

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.225:3000`, El wappalizer no nos muestra nada. Si entramos con la url `http://10.10.10.225:5000` vemos el panel de inicio de
session y el wappalizer tampoco no dice nada.

El puerto 3000 nos muestra un GITEA, intentamos cosas como XSS, Regex y SQLi en el input del menu Explorar, pero no vemos nada. En usuarios vemos 3 usuarios:

- david
- marcus
- root

Si pinchamos en los links de los usuarios no vemos nada. Tambien vemos que no nos podemos registrar. Intentamos loggearnos como `david:david`, `marcus:marcus` y `root:root` pero nada.

En la pagina del puerto 5000, nos podemos registrar. Creamos un usuario y entramos en una web. miramos si podemos hacer cosas como htmlI, XXS, pero no vemos nada. Lo unico seria
en la pagina `http://10.10.10.225:5000/notes` que podriamos Fuzzear para ver notas.

Lanzamos Burpsuite para ver como se transmitten las peticiones. Pero no vemos nada interesantes aqui.





