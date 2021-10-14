## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.3
```
ttl: 63 -> maquina Linux

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.3
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.3 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p21,22,139,445,3632 10.10.10.3 -oN targeted
```


| Puerto | Servicio | Que se nos occure?          | Que falta?           |
| ------ | -------- | --------------------------- | -------------------- |
| 21     | ftp      | Conexion como Anonymous     |                      |
| 22     | ssh      | Conneccion directa          | usuario y contraseña |
| 139    | smbd     | Conneccion con Null session |                      |
| 445    | smbd     | Conneccion con Null session |                      |
| 3632   | distccd  | Web, Fuzzing                |                      |



### Conexion Anonymous con ftp {-}

```bash
ftp 10.10.10.3

Name: anonymous
Password: 

Login successful

ls
```

Podemos connectar como anonymous pero no nos reporta nada. El resultado de nmap nos da que el vsftpd es de version 2.3.4.


