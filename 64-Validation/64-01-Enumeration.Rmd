## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.11.116
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.11.116
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.11.116 -oG allPorts 
extractPorts allPorts
nmap -sCV -p22,80,4566,8080 10.10.11.116 -oN targeted
```


| Puerto | Servicio   | Que se nos occure? | Que falta? |
| ------ | ---------- | ------------------ | ---------- |
| 22     | ssh        | Coneccion directa  |            |
| 80     | http       | Fuzzing            |            |
| 4566   | kwtc       |                    |            |
| 8080   | http proxy |                    |            |


### Analysando el puerto 80 {-}

#### Whatweb {-}

```bash
whatweb http://10.10.11.116
```

Vemos que estamos frente una maquina Debian con un apache 2.4.48 y PHP 7.4.23

```bash
whatweb http://10.10.11.116:8080
```

Esto nos muestra un bad gateway.

#### Analysis manual {-}

Con firefox vamos a la url `http://10.10.11.116` y vemos una pagina que nos permite registrar personas

```bash
admin - Brazil
s4vitar - Brazil
```

Intentamos cosas

```bash
<h1>Hola</h1>
```

Vemos que la web es vulnerable a HTML Injection.


```bash
<script>alert("hola")</script>
```

Y tambien a injeccion XSS. Pero como no estamos ni si quiera authenticado, no vamos a poder robar nada.

```bash
admin'
```

Nos pone `admin'`. Vamos a ver si el input del pays es vulnerable, para esto utilizamos burpsuite.

