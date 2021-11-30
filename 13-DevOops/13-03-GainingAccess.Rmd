## Explotacion de vulnerabilidad & Ganando Acceso {-}

### Conexion por SSH {-}

Como ya tenemos una id_rsa nos conectaremos como el usuario roosa

```bash
chmod 600 id_rsa
ssh -i id_rsa roosa@10.10.10.91
```

Ya estamos conectados como Roosa y podemos leer la flag.





