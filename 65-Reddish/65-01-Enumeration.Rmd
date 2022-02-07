## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.94
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.94
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.94 -oG allPorts 
extractPorts allPorts
nmap -sCV -p1880 10.10.10.94 -oN targeted
```


| Puerto | Servicio             | Que se nos occure? | Que falta? |
| ------ | -------------------- | ------------------ | ---------- |
| 1880   | http Node.js Express | Coneccion directa  |            |


### Analysando el puerto 80 {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.94:1880
```

No vemos nada interessante

#### Analyzando routas con NMAP {-}

```bash
nmap --script http-enum -p1880 10.10.10.94 -oN webScan
```

No vemos nada.

#### Analysis manual {-}

Con firefox vamos a la url `http://10.10.10.94` y vemos una pagina que nos dice que el GET no esta permitido para esta pagina. Le lanzamos un curl

```bash
curl -s -X GET "http://10.10.10.94:1880"
curl -s -X POST "http://10.10.10.94:1880"
curl -s -X POST "http://10.10.10.94:1880" | jq

#Output
{
    "id":"e6fae2bb0098d336bf34ab00a5978700",
    "ip":"::ffff:10.10.14.29",
    "path":"/red/{id}"
}
```

Si tratamos de ir desde firefox a la url `http://10.10.10.94/red/e6fae2bb0098d336bf34ab00a5978700` entramos en un Node-RED. 
