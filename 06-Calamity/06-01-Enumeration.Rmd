## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.27
```
ttl: 63 -> maquina linux. 
Recuerda que tratandose de ttl 64 = linux y 128 = windows. 
Pero como estamos en hackthebox hay un nodo intermediario que hace que el ttl disminuya una unidad

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.27 -oG allports
extractPorts allPorts
nmap -sC -sV -p22,80 -oN targeted
```

|Puerto|Servicio    | Que se nos occure?                  |    Que falta?      |
|------|------------|-------------------------------------|--------------------|
|22    |ssh         |Accesso directo                      |usuario y contraseña|
|80    |http        |Analizis de la web y Fuzzing         |                    |

### Analizando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.197
```

#### http-enum {-}

Lanzamos un web scan con nmap.

```bash
nmap --script http-enum -p80 10.10.10.27 -oN webScan
```

Ya nos detecta un `/admin.php` y un directorio `/uploads/`

#### Checkear la web del puerto 80 {-}

Abrimos la web y vemos cosas:

- El wappalizer no nos dice nada
- parece que todavia la web esta en fase de desarollo
- el directorio `/uploads/` muestra una capacidad de directory listing pero no se ve gran cosa
- el `/admin.php` nos muestra un login.
- haciendo un `Ctrl-U` no muestra una contraseña en un comentario ;)




