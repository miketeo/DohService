Building
========

Install additional dependencies for development as superuser
```
$> apt-get install libz-dev libbz2-dev automake autoconf bison flex make wget
```

Make the deps folder under the project root if it does not exist
```
$> mkdir deps
```

Then go to deps-src and build the rest of the dependencies as developer user
```
$> cd deps-src && make
```

Getting SSL certificate
=======================

I use acme.sh from [acme.sh)(https://github.com/Neilpang/acme.sh) to prepare the SSL certificate
on my local development node. You can also use [https://certbot.eff.org/](certbot) for your public
DOH service.

Running
=======

After building the application and preparing your SSL certificates, run the following command.
Remeber to replace <keyfile> and <certfile> with the correct paths to your SSL certificate private key
and your full-chain cert file (containing both the CA and SSL certificates).
```
$> ./DohService --port=10443 --dns=8.8.8.8,8.8.4.4 <keyfile> <certfile>
```

Testing
=======

```
$> cd test && make
$> ./DohTest https://127.0.0.1:10443/dns-query A google.com github.com
```
