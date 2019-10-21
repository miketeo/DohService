Frequently-Asked Questions
==========================

**Can I use other upstream DNS servers?**

Yes, you can use other public DNS servers from other providers like Google, Cloudflare and Quad9. You can even use your own DNS services.

**How do I prevent the IP address and DNS query information being output?**

Edit ```log.conf``` and upgrade the rule in the [rules] from *INFO* to *NOTICE* like the following:
```
[rules]
ds_.NOTICE >stdout; local
```

If you wish to customize the log format or to redirect the output to log files, please consult the documentation at [zlog](https://hardysimpson.github.io/zlog/UsersGuide-EN.html#htoc14) for more information.

**Do I need to run DohService as superuser?**

If you are not listening on port 443 (IANA designated port for HTTPS), you do not need and should not run DohService as superuser.

I will recommend running DohService under another port number (higher than 1024 which will avoid the need for superuser privileges). You can specify the port number via the ```--port```. Example to listen on port 10443,
```
DohService --port=10443 --dns=208.67.222.222,208.67.220.220 <SSL-key-file> <SSL-cert-fullchain-file>
```

If you are running DohService as another user, please ensure that the user has read-write access to log.conf and the folder.

**DohService fails to run with error: "unable to init log from log.conf"**

Please ensure that the user has read-write access to log.conf and the folder. If this cannot be done, please add the ```rotate lock file``` parameter in log.conf
```
[global]
rotate lock file = /tmp/dohservice.lock
```

**Why is libjemalloc.so bundled in DohService.zip?**

[jemalloc](http://jemalloc.net/) is a malloc implementation that helps to avoid memory fragmentation that could happen for long running applications.

I have chosen not to link to jemalloc directly in the DohService. Instead, if you are interested to use jemalloc, you can start inject it into the DohService at runtime like this:
```
$bash> LD_PRELOAD=/opt/dohservice/libjemalloc.so /opt/dohservice/DohService ...
```

**How do I run DohService as a daemon service?**

DohService is not designed to run as a daemon service. However, you can run DohService under other process control systems like [supervisord](http://supervisord.org/) or runit.

The following is the configuration for supervisord which runs the DohService under *www-data* user.
```
[program:dohservice]
environment=LD_PRELOAD="/opt/dohservice/libjemalloc.so"
command=/opt/dohservice/DohService --port=10443 --dns=208.67.222.222,208.67.220.220 /etc/letsencrypt/live/dns.example.com/privkey.pem /etc/letsencrypt/live/dns.example.com/fullchain.pem
directory=/opt/dohservice
user=www-data
autorestart=true
stdout_logfile=/var/log/supervisor/dohservice_stdout.log
stderr_logfile=/var/log/supervisor/dohservice_stderr.log
```
