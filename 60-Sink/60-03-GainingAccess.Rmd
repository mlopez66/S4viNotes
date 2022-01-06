## Vuln exploit & Gaining Access {-}

### GITEA Git commits history {-}

Loggeado como el usuario **root** nos permitte ver 4 repositorios. Aqui tenemos que analyzar los differentes repositorios que nos permitte encontrar
nuevos puertos internos, un proyecto `elastic_search`, un repositorio `Log_Manager` que contiene informaciones sobre un **aws** y otras informaciones mas.

Uno de los proyecto es el **Key_Management** que es archivado, y que contiene commits hechos por el usuario marcus. Uno de estos commits contiene una 
`Private key`.

Copiamos la llave y le ponemos derechos **600**, nos podemos connectar por `ssh` como el usuario `marcus`.

```bash
chmod 600 id_rsa
ssh -i id_rsa marcus@10.10.10.225
```

Aqui podemos ver que hemos ganado accesso al systema y que podemos leer la flag.


