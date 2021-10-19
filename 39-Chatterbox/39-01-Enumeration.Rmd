## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.74
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.74
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.74 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p9255,9256 10.10.10.74 -oN targeted
```


| Puerto | Servicio          | Que se nos occure? | Que falta? |
| ------ | ----------------- | ------------------ | ---------- |
| 9255   | http AChat        | Web, Fuzzing       |            |
| 9256   | achat chat system |                    |            |


