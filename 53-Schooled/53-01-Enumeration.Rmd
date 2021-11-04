## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.234
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.234
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.234 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80,443 10.10.10.234 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | tcp      | Conneccion directa | creds      |
| 80     | http     | Web, Fuzzing       |            |
| 33060  | mysql?   | SQLI               |            |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.234
```

Es un Apache 2.4.46 en un **FreeBSD** con PHP 7.4.15. Vemos un email `admission@schooled.htb`, añadmimos el dominio al `/etc/hosts`.


#### Checkear la web {-}

Si entramos en la url `http://10.10.10.234` o `http://schooled.htb` vemos lo mismo. El wappalizer no nos muestra nada interessante.
No vemos commentarios interessante en el codigo fuente. Si pinchamos al link **About**, vemos que la pagina se carga con una animacion.
Investigamos lo que ocure al lado del servidor con **BurpSuite** pero no vemos nada.
En la pagina `http://10.10.10.234/about.html` vemos probables usuarios en el testimonials. En la pagina `http://10.10.10.234/teachers.html` 
vemos mas usuarios potenciales. Decidimos crear un diccionario con estos usuarios por si acaso.

```bash
vi users

James Fernando
j.fernando
jfernando
Jacques Philips
j.philips
jphilips
Venanda Mercy
v.mercy
vmercy
Jane Higgins
j.higgins
jhiggins
Lianne Carter
l.carter
lcarter
Manuel Phillips
m.phillips
mphillips
Jamie Borham
j.borham
jborham
```

#### Fuzzing {-}

```bash
nmap --script http-enum -p80 10.10.10.234 -oN webScan
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.234/FUZZ
```

Como no encontramos nada interessante, vamos a enumerar subdominios con **WFUZZ**

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "Host: FUZZ.shooled.htb http:10.10.10.234
wfuzz -c -t 200 --hc=404 --hl=461 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "Host: FUZZ.shooled.htb http:10.10.10.234
```

Encontramos un subdominio `moodle.schooled.htb`, lo añadmimos al `/etc/hosts`.




