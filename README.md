About DohService
================

DohService receives incoming DNS query requests from supported web browsers using DNS-over-HTTPS (DOH) protocol, and then resolves the hostnames in these requests using other upstream DNS services on port 53.

When Mozilla announced rollout of DOH, critics criticized its decision as DOH can break DNS-based content filters that had been put in place to deny access to explicit, obscene or otherwise objectionable web sites.

Personally, I like the idea of a secure DNS service as I often access the web on my laptop using public Wifi services where there are risks of DNS poisoning and data privacy issues.

With DohService, I can now setup my personal DOH service on a publicly-accessible Internet server. When I configure DohService to use [OpenDNS](https://www.opendns.com/) as the upstream DNS servers, I can also register the DohService's IP address and have a more customized web site filtering experience through OpenDNS filtering options.

With this setup, I have a more personalized DNS filtering capability (through OpenDNS) along with the privacy protection offered by DOH.

Building
========

To build the DohService, please refer to the [INSTALL.md](INSTALL.md) file.

Questions and Issues
====================

Please check out the [FAQs.md](FAQs,md) or file a ticket on the issues section at the project web site on github.

License
=======

DohService is licensed under zlib license. Please check the [LICENSE.md](LICENSE.md) file for more details.
