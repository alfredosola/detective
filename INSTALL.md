# Detective: Find nefarious activity in mail log

See [README.md](https://github.com/alfredosola/detective/blob/master/README.md). for general information on Detective.

## Quick install

Commands in this file are tested on a Debian 11 system. They should work on Ubuntu and other derivatives too, and on many other distributions with little adaptations.

### Install required libraries and stuff
Detective needs the Python 3 yaml, redis, geoip2 and geopy libraries, plus MaxMind's GeoIP basic kit, and a Redis server.

On a Debian system, this is done with a one-liner:

```bash
sudo apt --yes install python3 python3-yaml python3-redis redis-server python3-geoip2 geoipupdate python3-geopy geoip-database
```

### Configure GeoIP
You need a Maxmind accout (a free one is enough for our purposes) to keep the IP geolocation database current.

Edit `/etc/GeoIP.conf` and set your AccountID and LicenseKey.

Then, run geoipupdate for the first time to download the database:
```bash
sudo /usr/bin/geoipupdate
```

### Install main program

Copy `detective.py` somewhere appropriate, e.g.:
```bash
sudo wget -O /usr/local/bin/detective.py https://raw.githubusercontent.com/alfredosola/detective/master/detective.py
```

Take a look at the source code, and then give it permission to run:
```bash
sudo chmod +x /usr/local/bin/detective.py
```
### Run Detective

You can run Detective on a console to give it a go:
```bash
sudo /usr/local/bin/detective.py
```

Detective doesn't need root unless listening on a privileged port. It does need to write to its log file. If you prefer to run it with a separate user, which is recommended, then create a system user (let's call it detective) and touch its logfile:

```bash
sudo useradd --system detective
sudo touch /var/log/detective.log
sudo chown detective /var/log/detective.log
```

Then you can run detective with its own user:
```bash
sudo -u detective /usr/local/bin/detective.py
```

## Feed Detective: Syslog
Detective listens to syslog on UDP. You need an availlable socket for that. The default is known to work in most circumstances.

In order to forward syslog to detective, if you are using rsyslog (the default syslog on Debian), the easiest option is to add this line to rsyslog's configuration:

`mail.*  action(type="omfwd" target="127.0.0.1" port="10514" protocol="udp")`

You would typically drop this as a configuration snippet on rsyslog configuration directory, e.g.:

```bash
echo 'mail.*  action(type="omfwd" target="127.0.0.1" port="10514" protocol="udp")' | sudo tee /etc/rsyslog.d/detective.py
```

Do not forget to have rsyslog read its new configuration. E.g., on systemd systems:
```bash
sudo systemctl restart rsyslog
```

## Send syslog from other sources

If you want to forward syslog from a bunch of servers, you may use an rsyslog configuration such as

`mail.*  action(type="omfwd" target="10.34.91.5" port="514" protocol="udp")`

on the other servers' rsyslog configuration. This forwards only the mail topic, which filters out a lot of other stuff that Detective would not process anyway, thus avoiding a lot of waste.

## Using Detective
### Look at the logfile

Let detective run for some time. If there is any problem, it will throw an exception to the console.

After some time (depending on how much syslog is being thrown at detective), it will begin saying things on the logfile.

### Logwatch

logwatch is a utility that will keep looking at the logfile and advise if any alert is found. It can send you an e-mail when the patterns for Yellow and/or Red alerts are seen. For details, please look at the [logwatch site](https://sourceforge.net/projects/logwatch/)

### fail2ban

A jail to ban the IP from where the user logs in is almost trivial to write. Note that, since Detective has no way of knowing which IP the legitimate user is logging in from, you would probably want to ban both. This will temporarily break the user's e-mail, which can be the desired effect: There is no better way to grab a user's attention than breaking their e-mail!

## Rotate the logfile

Detective does not rotate its own logfile. It is recommended to use logrotate for that. This will work on Debian systems:

```bash
sudo -i
cat > /etc/logrotate.d/detective <<EOF
/var/log/detective.log {
	monthly
	rotate 12
	compress
	delaycompress
	missingok
	notifempty
	create 644 detective root
}
EOF
```

Then, restart logrotate:
```bash
systemctl restart logrotate
```

## Run detective automatically on system boot

Drop an init script or unit system as appropriate for your system.

For a systemd system, you can find a suitable file on this repo:
```bash
sudo wget -O /lib/systemd/system/detective.service https://raw.githubusercontent.com/alfredosola/detective/master/detective.service
sudo systemctl enable detective
```

## Help and feedback

Please see the section about issues of the [README.md](https://github.com/alfredosola/detective/blob/master/README.md) for information. TL;DR: Open an issue in this repo.

## Contributions

Please see the Contributions section of the [README.md](https://github.com/alfredosola/detective/blob/master/README.md) for information on contributing. TL;DR: Contributions are accepted, just open an issue to talk about it first.

## License

Detective is licensed under the GNU General Public License v3.0. See [LICENSE](https://github.com/alfredosola/detective/blob/master/LICENSE).
