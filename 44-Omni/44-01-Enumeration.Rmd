## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.204
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.204
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.204 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p135,5985,8080,29817,29819,29820 10.10.10.204 -oN targeted
```


| Puerto | Servicio | Que se nos occure?             | Que falta?   |
| ------ | -------- | ------------------------------ | ------------ |
| 135    | msrpc    | rpcclient con nul session      |              |
| 5985   | WinRM    | evil-winrm                     | credenciales |
| 8080   | http     | Web Fuzzing                    |              |
| 29817  | msrpc    | Puertos por defecto de windows |              |
| 29819  | msrpc    | Puertos por defecto de windows |              |
| 29820  | msrpc    | Puertos por defecto de windows |              |

### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.204:8080
```

Es un Windows Device Portal con un HTTPapi y un WWW-Athentication.

#### Checkear la web {-}

Si entramos en la url `http://10.10.10.204:8080`, Vemos un panel basic authentication.


#### Checkeando la cavezera con curl {-}

```bash
curl -s -X GET "http://10.10.10.204:8080"
curl -s -X GET "http://10.10.10.204:8080" -I
```

Vemos en la cabezera que el basic-auth es sobre un `Windows Device Portal`
Buscamos si existe una vulnerabilidad asociada en google poniendo `Windows Device Portal github exploit` y encontramos
una pagina interesante de [SirepRAT](https://github.com/SafeBreach-Labs/SirepRAT) que nos permitiria ejecutar RCE.
