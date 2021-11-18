## Escalada de privilegios {-}

### Rootear la maquina {-}

```bash
sudo -l
#Output
(ALL : ALL) ALL
```

Vemos que el usuario notch puede efectuar cualquier comando como qualquier usuario ;)

```bash
sudo su
whoami

root
```

Ya esta ;)
