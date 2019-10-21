Building
========

DohService was developed on Ubuntu 16.04 LTS (x64). It should compile on other later Ubuntu releases.

Install additional dependencies for development as superuser
```
$> apt-get install libz-dev libbz2-dev libexpat1-dev automake autoconf bison flex make wget
```

Make the deps folder under the project root if it does not exist
```
$> mkdir deps
```

Then go to deps-src and build the rest of the dependencies as developer user
```
$> cd deps-src && make
```

To build the DohService, go to src folder and run make
```
$> cd src && make
```

You can package DohService and all the required dependencies into a zip file (DohService.zip). Then, you can copy the DohService.zip file to the remote server and unzip it in the target folder.
```
$> cd src && make dist
```

If you encounter issues, you may file a ticket on the project website at github,
or check the [FAQs.md](FAQs.md) file.

Getting SSL certificate
=======================

I use [acme.sh](https://github.com/Neilpang/acme.sh) to prepare the SSL certificate
on my local development node. You can also use [certbot](https://certbot.eff.org/) to get a free SSL certificate for your public DOH service.

Running
=======

After building the application and preparing your SSL certificates, run the following command.
Remeber to replace **keyfile** and **certfile** with the correct paths to your SSL certificate private key
and your full-chain SSL cert file (containing both the CA and SSL certificates).
```
$> ./DohService --port=10443 --dns=8.8.8.8,8.8.4.4 <keyfile> <certfile>
```

On FireFox and other DOH-supported web browsers, you can then fill in this URL **https://[hostname]:10443/dns-query** in the DOH URL field on the configuration settings.

Testing
=======

```
$> cd test && make
$> ./DohTest https://127.0.0.1:10443/dns-query A google.com github.com
```
