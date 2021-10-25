## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.171
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.171
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.171 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.171 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 22     | tcp      | Conneccion directa | creds      |
| 80     | tcp      | Web, Fuzzing       |            |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.171
```

Es un Apache 2.4.29 en un Ubuntu. 


#### Checkear la web {-}

Si entramos en la url `http://10.10.10.171`, Vemos la Apache2 default page.

#### Fuzzing con WFuzz {-}

```bash
wfuzz -c -t 200 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.171/FUZZ
```

Vemos un directorio `/arcwork` que no nos muestra gran cosa. Tambien vemos un directorio `/music` y vemos que el login nos lleva a un directorio
`/ona`

Pinchamos y llegamos a un panel de administracion de `opennetadmin`
