# Detective: Find nefarious activity in mail log

Follow Tecnocrática on Twitter: [@TecnocraticaCPD](https://twitter.com/TecnocraticaCPD)

## Why?

The CEO scam. The new bank account scam. Many of today's most successful and insidious threats come in the form of a legitimate-looking e-mail, after a breach of someone's e-mail.

In many of those, the attackers log in to the victim's (or the victim's business partner) e-mail well in advance of the execution of their attack. They usually do it from somewhere far from the legitimate user, like a VPN or a residential connection in a far away country. And that situation can be detected automatically. Why not keep watch for that?

## What?

The Log Detective (or Detective for short) is a small utility that sits in the background ingesting mail logs and will raise an alarm when something concerning happens. Concerning, in this case, means a very likely (aiming for 100% accuracy) breach of a user's e-mail account security.

## How?

Detective has a syslog listener that decodes Postfix SASL and Dovecot IMAP logins in real time. Then, it finds and geolocates its IP addresses. When the IP has changed, it calculates the physical distance between the previous action and the current one. If it finds two actions that happen impossible in space-time, like logging in from cities thousands of kilometers away within minutes, it raises an alarm.

Using MaxMind's GeoIP City database (an account is required, a free account is enough for this purpose) and a simple Python program that can be fed directly from syslog. See INSTALL.md for details.

Most users have e-mail set up to check automatically for new mail in the background, therefore inadvertedly maintaining a state. We leverage this to find sharp deviations from the state.

Optionally, a more severe alarm is raised if one of the IP addresses is geolocated to a country in which the users are known not to be or log in from.

## Who?

This was originally written for using in [Tecnocrática](https://tecnocratica.net) by one of its founders. I am hoping to contribute back to the community.

## False positives

Default parameters are chosen to minimize false positives. Still, certain circumstances can generate some:
- VPN users
- Mobile users switching from wifi to mobile data

Some of those fall below the error allowed for. For instance, the geolocation service finds that there are about 10 kilometers from my location with/without VPN, well below the default threshold.

## Installation

See [INSTALL.md](https://github.com/alfredosola/detective/blob/master/INSTALL.md).

## Configuration
| Parameter      | Usage                                                                                          | Default value                    |
|----------------|------------------------------------------------------------------------------------------------|----------------------------------|
| HOST, PORT     | Where to listen to syslog.                                                                     | 127.0.0.1 port 10514             |
| LOGFILE        | Write events to this log file.                                                                 | /var/log/detective.log           |
| DISTANCEMARGIN | Two IPs geolocated within this distance are considered to be in the same place.                | 100 km                           |
| SPEEDMARGIN    | Two logins separated this distance/time are considered fine.                                   | 1000 m/s (about thrice the speed of sound) |
| SUSPICIOUSCC   | Countries (in ISO 3166 2-letter format) where we believe none of our users are or log in from  | ['CN', 'RU']                     |

## Issues, bug reports, feedback

If you have any problem or want to provide feedback, please open an issue.

## Contributions

Contributors are welcome. Please open an issue to chat about what you want to do in advance.

Areas where contributions are regarded to be especially useful:
- General code quality improvements.
- Packaging for distributions.
- Use cases

That said, no contribution is too minor to be reviewed and hopefully accepted. Even a typo!

## License

The Log Detective is licensed under the GNU General Public License v3.0. See [LICENSE](https://github.com/alfredosola/detective/blob/master/LICENSE).
