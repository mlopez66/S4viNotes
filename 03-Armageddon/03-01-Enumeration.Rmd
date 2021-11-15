## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.233
```
ttl: 63 -> maquina linux. 
Recuerda que de ttl 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.233 -oG allPorts
extractPorts allPorts
nmap -sC -sV -p22,80 10.10.10.233 -oN targeted
```

- Drupal 7

|Puerto|Servicio| Que se nos occure?              |    Que falta?      |
|------|--------|---------------------------------|--------------------|
|22    |ssh     |Accesso directo                  |usuario y contraseña|
|80    |http    |Drupal-armageddon (drupalgeddon2)|Checkear el exploit |

#### Browsear la web {-}

Nada interessante.
