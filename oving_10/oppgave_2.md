# Øving 10, oppgave 2

Målet er å generere et selvsignert SSL-sertifikat og konfigure webserveren nginx til å bruke dette.

Vi genererer et selvsignert sertifikat med kommandoen:

```
$ sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt
```
`-nodes` spesifiserer at vi ikke ønsker å sette passord på privatnøkkelen.

Privatnøkkelen må uansett holdes hemmelig, vi begrenser derfor tilgangen:

```
$ sudo chmod 600 /etc/ssl/private/nginx-selfsigned.key
```

Så endrer vi serverkonfigurasjonen i fila `/etc/nginx/sites-available/default`. 
Direktivene `ssl_certificate` og `ssl_certificate_key` forteller hvor nginx finner sertifikatfilene:

```
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name testserver.no;

    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    
    ...
```

Vi restarter nginx, og kan dermed besøke nettsiden over HTTPS med selvsignert sertifikat.
