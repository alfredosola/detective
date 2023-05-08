#!/usr/bin/env python3

## Listen and react to suspicious activity in Postfix and Dovecot

## Copyright (C) 2023 Alfredo Sola <alfredo@tecnocratica.net>

##    This program is free software: you can redistribute it and/or modify
##    it under the terms of the GNU General Public License as published by
##    the Free Software Foundation, either version 3 of the License, or
##    (at your option) any later version.

##    This program is distributed in the hope that it will be useful,
##    but WITHOUT ANY WARRANTY; without even the implied warranty of
##    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##    GNU General Public License for more details.

##    You should have received a copy of the GNU General Public License
##    along with this program.  If not, see <https://www.gnu.org/licenses/>.

## Credits

## This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com

HOST, PORT = "127.0.0.1", 10514
LOGFILE = '/var/log/detective.log'
DISTANCEMARGIN = 100000 # m. Two IPs geolocated within this distance are considered to be in the same place. Default 100 km.
SPEEDMARGIN = 1000 # m/s. Two logins separated this distance/time are considered fine. Default 1000 m/s, about thrice the speed of sound.
SUSPICIOUSCC = ['CN', 'RU']

import re
import sys
import redis
import logging
import datetime
import socketserver
import geoip2.database
from geopy.distance import geodesic

logging.basicConfig(level=logging.INFO, format='%(message)s', datefmt='', filename=LOGFILE, filemode='a')

class reParser(object):
  def parse(self, object):
    regex_dovecot_login = re.compile(r"dovecot: imap-login: Login: user=<(?P<email>[\w.]+@[\w.]+)>.+rip=(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})")
    regex_smtpd_login = re.compile(r"postfix/smtpd.+client=.+\[(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\].+sasl_username=(?P<email>[\w.]+@[\w.]+)")
    payload              = {}

    m = regex_dovecot_login.search(object)
    if ( m ):
      payload["email"] = m.group('email')
      payload["ip"] = m.group('ip')
      payload["service"] = 'dovecot'
    else:
      m = regex_smtpd_login.search(object)
      if ( m ):
        payload["email"] = m.group('email')
        payload["ip"] = m.group('ip')
        payload["service"] = 'postfix'

    return payload

class SyslogUDPHandler(socketserver.BaseRequestHandler):

  def handle(self):
    reparser = reParser()
    r = redis.Redis(
      host='localhost',
      port=6379)

    data = bytes.decode(self.request[0].strip())
    socket = self.request[1]
    fields = reparser.parse(data)
    if ( fields != {} ):
      with geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-City.mmdb') as reader:
        geolocation = reader.city(fields["ip"])
      previous_action = r.hmget( fields["email"], "timestamp", "ip", "latitude", "longitude", "iso_code", "accuracy", "service" )
      if ( previous_action[0] != None ):
        previous_ip = previous_action[1].decode("utf-8")
        if ( fields["ip"] != previous_ip ):
          previous_timestamp = datetime.datetime.strptime(previous_action[0].decode("utf-8"),'%Y-%m-%d %H:%M:%S.%f')
          time_difference = datetime.datetime.now() - previous_timestamp
          previous_latitude = previous_action[2].decode("utf-8")
          previous_longitude = previous_action[3].decode("utf-8")
          previous_location = ( previous_latitude, previous_longitude )
          current_location = ( geolocation.location.latitude, geolocation.location.longitude )
          previous_country = previous_action[4].decode("utf-8")
          distance = geodesic( previous_location, current_location ).m
          speed = distance / time_difference.total_seconds()
          logging.debug(str(datetime.datetime.now()) + " Gray alert: " + fields["email"] + " came from " + previous_ip + " at " + str(previous_timestamp) + ", now from " + fields["ip"] + ", distance: " + str(round(distance/1000)) + " km, time " + str(time_difference) + ", speed " + str(round(speed)) + " m/s")
          # Now it gets interesting
          if ( distance > DISTANCEMARGIN and speed > SPEEDMARGIN ):
            if ( geolocation.country.iso_code in SUSPICIOUSCC ):
              logging.info(str(datetime.datetime.now()) + " Red alert: " + fields["email"] + " came from " + previous_ip + " at " + str(previous_timestamp) + ", now from " + fields["ip"] + " (" + geolocation.country.iso_code + "), distance: " + str(round(distance/1000)) + " km, time " + str(time_difference) + ", speed " + str(round(speed)) + " m/s")
            else:
              logging.info(str(datetime.datetime.now()) + " Yellow alert: " + fields["email"] + " came from " + previous_ip + " at " + str(previous_timestamp) + ", now from " + fields["ip"] + " (" + geolocation.country.iso_code + "), distance: " + str(round(distance/1000)) + " km, time " + str(time_difference) + ", speed " + str(round(speed)) + " m/s")
      r.hmset( fields["email"], {"timestamp": str(datetime.datetime.now()), "ip": fields["ip"], "latitude": geolocation.location.latitude, "longitude": geolocation.location.longitude, "iso_code": geolocation.registered_country.iso_code, "accuracy": geolocation.location.accuracy_radius, "service": fields["service"] } )

if __name__ == "__main__":
  try:
    server = socketserver.UDPServer((HOST,PORT), SyslogUDPHandler)
    server.serve_forever(poll_interval=0.5)

  except (IOError, SystemExit):
    raise
  except KeyboardInterrupt:
    print ("Crtl+C Pressed. Shutting down.")
