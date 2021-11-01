## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.114
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.114
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.114 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.114 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | tcp      | Conneccion directa | creds      |
| 80     | tcp      | Web, Fuzzing       |            |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.114
```

Hay una redirection hacia la routa `http://10.10.10.114/users_sign_in` y vemos un Cookie `_gitlab_session`.
Vemos que esta hosteada sobre un NGINX. 


#### Checkear la web {-}

Si entramos en la url `http://10.10.10.114`, Vemos la pagina de inicio de session de Gitlab pero no podemos registrarnos. Solo nos podemos loggear.
Intentamos con loggins por defecto pero no llegamos a conectarnos.
Como la enumeracion con **NMAP** nos a mostrado un `robots.txt`, miramos lo que hay por esta routa. Vemos una serie de routas ocultadas. Intentamos ver unas
cuantas y la unica que nos muestra algo interesante es la routa `http://10.10.10.114/help` donde vemos un fichero `bookmark.html`.

Hay una serie de links y haciendo *Hovering* vemos que el link Gitlab Login nos sale un script un javascript. Analyzando el codigo fuente, vemos una declaracion
de variable en hexadecimal. La copiamos y la decodificamos para ver lo que es.

```bash
echo "var _0x4b18=[&quot;\x76\x61\x6C\x75\x65&quot;,&quot;\x75\x73\x65\x72\x5F\x6C\x6F\x67\x69\x6E&quot;,&quot;\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64
&quot;,&quot;\x63\x6C\x61\x76\x65&quot;,&quot;\x75\x73\x65\x72\x5F\x70\x61\x73\x73\x77\x6F\x72\x64&quot;,&quot;\x31\x31\x64\x65\x73\x30\x30\x38\x31\x78&quot;]" | sed s/\&quot/\'/g
#Output
var _0x4b18=[';value';,';user_login';,';getElementById';,';clave';,';user_password';,';11des0081x';]
```

Como tenemos un usuario y una contraseña nos connectamos al panel de inicio.

