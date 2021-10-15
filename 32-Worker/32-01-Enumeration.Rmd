## Enumeracion {-}

### Reconocimiento de maquina, puertos abiertos y servicios {-} 

#### Ping {-}

```bash
ping -c 1 10.10.10.203
```
ttl: 127 -> maquina Windows

#### Nmap {-}

```bash
nmap -p- --open -T5 -v -n 10.10.10.203
```

Va lento

```bash
nmap -sS -p- --open --min-rate 5000 -vvv -n -Pn 10.10.10.203 -oG allPorts 
extractPorts allPorts
nmap -sC -sV -p80,3690,5985 10.10.10.203 -oN targeted
```


| Puerto | Servicio      | Que se nos occure?             | Que falta?   |
| ------ | ------------- | ------------------------------ | ------------ |
| 80     | http          | Web, Fuzzing                   |              |
| 3690   | svnserve      |                                |              |
| 5985   | WinRM         | evil-winrm                     | credenciales |


### Analyzando la web {-}

#### Whatweb {-}

```bash
whatweb http://10.10.10.203
```

Nos enfrentamos a un Microsoft IIS 10.0

### Analyzando svnserve {-}

La primera cosa que hay que hacer es buscar en internet lo que svn es. Tambien vamos buscando si es possible enumerar
un servicio svn.

```bash
which svn
svn -h
svn checkout svn://10.10.10.203
```

Aqui vemos que nos a cargado dos ficheros, como uno de ellos se llama `dimension.worker.htb` pensamos que se esta aplicando virtual hosting. En el 
fichero `moved.txt` vemos a demas otro dominio.
Añadimos al `/etc/hosts` los dominios `worker.htb dimension.worker.htb devops.worker.htb`.

### Analyzando la web con Firefox {-}

Entramos en el panel IIS por defecto. Si lanzamos `http://worker.htb` sigue siendo lo mismo. Si le damos a `http://dimension.worker.htb` entramos
a una nueva web y si vamos al url `http://devops.worker.htb` hay un panel de session.

Aqui necessitamos credenciales, tenemos que volver al analysis de **svnserve** para ver si encontramos mas cosas

### Siguiendo el analysis svnserve {-}

```bash
svn checkout --help
```

Aqui vemos que hay un parametro de revision que por defecto esta a 1, miramos que pasa cuando le damos a 2

```bash
svn checkout -r 2 svn://10.10.10.203
cat deploy.ps1
```

Vemos algo nuevo, un fichero `deploy.ps1` y ya nos lo a descargado. Aqui ya vemos credenciales.

Intentamos connectar con **evil-winrm** pero no podemos. Vamos a por el panel de session de `http://devops.worker.htb` y aqui ya hemos podido
arrancar session. Es un Azure DevOps.

### Vulnerar un Azur DevOps {-}

Si navigamos en la web podemos ver multiples repositorios.

```{r, echo = FALSE, fig.cap="Azure DevOps repositories", out.width="90%"}
    knitr::include_graphics("images/Worker-repos.png")
```

Lo que nos llama la atencion aqui es el echo que hay un repositorio llamado dimension, y como existe un dominio `dimension.worker.htb`, pensamos que
los repositorios corresponden a proyectos relacionados con subdominios. Si añadimos el subdominio `alpha.worker.htb` en el `/ect/hosts` y que miramos con
el firefox a esta url vemos el proyecto. 

Si analysamos mas el proyecto, vemos que no podemos alterar el proyecto en la rama Master, y vemos que hay Pipelines que se lanzan automaticamente. Analysando 
el script de la Pipeline, vemos que no esta atada a la rama master.

Creamos una rama al proyecto y le ponemos nuestro codigo malicioso copiada del github de [borjmz aspx reverse shell](https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx)








