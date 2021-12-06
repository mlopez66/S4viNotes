## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.95
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.95
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.95 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p8080 10.10.10.95 -oN targeted
```


| Puerto | Servicio | Que se nos occure? | Que falta? |
| ------ | -------- | ------------------ | ---------- |
| 8080   | http     | Web Fuzzing        |            |


### Analyzando la web {-}


#### Http Enum {-}

```bash
nmap --script http-enub -p8080 10.10.10.95 -oN webScan
```



