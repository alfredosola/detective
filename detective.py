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
EMAILALLOWLIST = '/etc/detective/emailallowlist.txt' # Do not generate alerts for the emails in this list.
NETALLOWLIST = '/etc/detective/netallowlist.txt' # Do not generate alerts for the IPs contained in the networks listed here.
DISTANCEMARGIN = 100000 # m. Two IPs geolocated within this distance are considered to be in the same place. Default 100 km.
SPEEDMARGIN = 1000 # m/s. Two logins separated this distance/time are considered fine. Default 1000 m/s, about thrice the speed of sound.
DISTANCEMARGINWITHINCOUNTRY = 500000 # m. Two IPs geolocated within this distance are considered to be in the same place if CC is the same. Default 500 km.
SPEEDMARGINWITHINCOUNTRY = 2000 # m/s. Two logins separated this distance/time are considered fine if CC is the same. Default 2000 m/s.
SAMECCISGRAY = True # True if locating in the same country makes otherwise yellow or red alerts gray. Useful for false positive reduction.
SUSPICIOUSCC = ['CN', 'RU']

import re
import sys
import redis
import logging
import datetime
import ipaddress
import socketserver
import geoip2.database
from geopy.distance import geodesic

logging.basicConfig(level=logging.INFO, format='%(message)s', datefmt='', filename=LOGFILE, filemode='a')

class reParser(object):
  def parse(self, object):
    regex_dovecot_login = re.compile(r"dovecot: imap-login: Login: user=<(?P<email>[\w.]+@[\w.]+)>.+rip=(?P<ip>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[0-9A-Fa-f]{1,4}):){7}(?:[0-9A-Fa-f]{1,4})),")
    regex_smtpd_login = re.compile(r"postfix/smtpd.+client=.+\[(?P<ip>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[0-9A-Fa-f]{1,4}):){7}(?:[0-9A-Fa-f]{1,4}))\],.+sasl_username=(?P<email>[\w.]+@[\w.]+)")
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

  def is_ip_allowlisted(self,ip):
    try:
      ip_address = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
      try:
        ip_address = ipaddress.IPv6Address(ip)
      except ipaddress.AddressValueError:
        raise ValueError('Invalid IP address format')
    try:
      with open(NETALLOWLIST, 'r') as f:
        networks = f.read().splitlines()
    except FileNotFoundError:
      return False
    network_addresses = []
    for network in networks:
      try:
        network_address = ipaddress.IPv4Network(network)
      except ipaddress.AddressValueError:
         try:
            network_address = ipaddress.IPv6Network(network)
         except ipaddress.AddressValueError:
            raise ValueError(f'Invalid network format: {network}')
      network_addresses.append(network_address)

    for network_address in network_addresses:
      if ip_address in network_address:
        return True
    return False

  def is_email_allowlisted(self,email):
    try:
      with open(EMAILALLOWLIST, 'r') as emailallowlistfile:
        allowlist=emailallowlistfile.read()
      if (email in allowlist ):
        return True
      else:
        return False
    except FileNotFoundError:
      return False

  def handle(self):
    self.r = redis.Redis( host='localhost', port=6379)
    reparser = reParser()
    data = bytes.decode(self.request[0].strip())
    socket = self.request[1]
    fields = reparser.parse(data)
    if ( fields == {} ):
      return
    logging.debug(str(datetime.datetime.now()) + " Decoded: " +
      " service: " + fields["service"] +
      " email: " + fields["email"] +
      " IP: " + fields["ip"] + ".")
    if ( self.is_email_allowlisted(fields["email"]) ):
      logging.debug(str(datetime.datetime.now()) + " Allowlisted email: " + fields["email"] +" ("+fields["ip"]+")")
      return
    if ( self.is_ip_allowlisted(fields["ip"]) ):
      logging.debug(str(datetime.datetime.now()) + " Allowlisted IP: " + fields["email"] +" ("+fields["ip"]+")")
      return
    with geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-City.mmdb') as reader:
      geolocation = reader.city(fields["ip"])
    previous_action = self.r.hmget( fields["email"], "timestamp", "ip", "latitude", "longitude", "iso_code", "accuracy", "service" )
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
        logging.debug(str(datetime.datetime.now()) + " Gray alert: " + fields["email"] + " came from " + previous_ip + " at " + str(previous_timestamp) +
                      ", now from " + fields["ip"] + ", distance: " + str(round(distance/1000)) + " km, time " + str(time_difference) + ", speed " + str(round(speed)) + " m/s")
        # Now it gets interesting
        if ( ( distance > DISTANCEMARGINWITHINCOUNTRY and speed > SPEEDMARGINWITHINCOUNTRY )
             and ( previous_country == geolocation.registered_country.iso_code and not SAMECCISGRAY )
           or
             ( distance > DISTANCEMARGIN and speed > SPEEDMARGIN and previous_country != geolocation.registered_country.iso_code ) ):
          log_data = fields["email"] + " came from " + previous_ip + " (" + previous_country + "), at " + str(previous_timestamp) + \
                                       ", now from " + fields["ip"] + " (" + geolocation.country.iso_code + "), distance: " + \
                                       str(round(distance/1000)) + " km, time " + str(time_difference) + ", speed " + str(round(speed)) + " m/s"
          if ( geolocation.country.iso_code in SUSPICIOUSCC ):
            logging.info(str(datetime.datetime.now()) + " Red alert: " + log_data)
          else:
            logging.info(str(datetime.datetime.now()) + " Yellow alert: " + log_data)
      try:
        key = fields["email"]
        iso_code = geolocation.registered_country.iso_code if geolocation.registered_country.iso_code is not None else "--"
        content = { "timestamp": str(datetime.datetime.now()), "ip": fields["ip"],
                    "latitude": geolocation.location.latitude, "longitude": geolocation.location.longitude,
                    "iso_code": iso_code, "accuracy": geolocation.location.accuracy_radius, "service": fields["service"] }
        self.r.hmset( key, content )
      except:
        logging.info(str(datetime.datetime.now()) + " Exception sending to Redis: " + str(content))

if __name__ == "__main__":
  try:
    server = socketserver.UDPServer((HOST,PORT), SyslogUDPHandler)
    server.serve_forever(poll_interval=0.5)

  except (IOError, SystemExit):
    raise
  except KeyboardInterrupt:
    print ("Crtl+C Pressed. Shutting down.")
