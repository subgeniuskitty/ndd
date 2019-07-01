# Overview #

Install or uninstall an SMF service named svc:/site/ndd:default.

Tested on Solaris 11.3.

Run either `install.sh` or `uninstall.sh` without further options.

# SMF Properties #

`ndd` SMF properties and default values:

    # svccfg -s svc:/site/ndd:default
    svc:/site/ndd:default> listprop ndd
    ndd              application
    ndd/binary_path  astring     /usr/local/bin
    ndd/config_file  astring     /usr/local/etc/ndd.ini
    ndd/lock_file    astring     /var/spool/locks/ndd.lock
