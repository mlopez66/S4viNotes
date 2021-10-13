## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.55
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.55
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.55 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,8009,8080,60000, 10.10.10.55 -oN targeted
```


| Puerto | Servicio    | Que se nos occure? | Que falta?           |
| ------ | ----------- | ------------------ | -------------------- |
| 22     | ssh         | Conneccion directa | usuario y contraseña |
| 8009   | tcp ajp13   | Web, Fuzzing       |                      |
| 8080   | http tomcat | Web, Fuzzing       |                      |
| 60000  | http apache | Web, Fuzzing       |                      |



### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.55:8080
```

Nada interressante aqui

#### Checkear la web por los differentes puertos {-}

- El puerto 8009 no sale Nada.
- El puerto 8080 nos saca un 404
- El puerto 60000 nos sale una pagina

La pagina en el puerto 60000 parece ser un web browser que podriamos utilizar para navigar sobre otras paginas web de manera anonyma.

Creamos nuestro proprio servidor web para ver lo que pasa.

```bash
vi index.html

Hola, Vodafone apestais y sois los peores....
```

Compartimos un servidor web con python

```bash
python3 http.server 80
```

Si desde la web lanzamos un `http://10.10.14.6` vemos nuestra pagina web. Intentamos crear una pagina php pero no funcciona. 

