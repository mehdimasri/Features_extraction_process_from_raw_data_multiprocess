#!/usr/bin/env python3
import socket
import sys
import json

from argparse import ArgumentParser, SUPPRESS
from datetime import datetime
from ssl import PROTOCOL_TLSv1
from time import sleep
from csv import DictWriter

try:
    from OpenSSL import SSL
    from json2html import *
except ImportError:
    print('Please install required modules: pip install -r requirements.txt')
    sys.exit(1)


class Clr:
    """Text colors."""

    RST = '\033[39m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'


class SSLChecker:

    total_valid = 0
    total_expired = 0
    total_failed = 0
    total_warning = 0

    def get_cert(self, host, port):
        """Connection to the host."""

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        osobj = SSL.Context(PROTOCOL_TLSv1)
        sock.connect((host, int(port)))
        oscon = SSL.Connection(osobj, sock)
        oscon.set_tlsext_host_name(host.encode())
        oscon.set_connect_state()
        oscon.do_handshake()
        cert = oscon.get_peer_certificate()
        sock.close()
        return cert


    def border_msg(self, message):
        """Print the message in the box."""
        row = len(message)
        h = ''.join(['+'] + ['-' * row] + ['+'])
        result = h + '\n' "|" + message + "|"'\n' + h
        print(result)



    def get_cert_sans(self, x509cert):
        """
        Get Subject Alt Names from Certificate. Shameless taken from stack overflow:
        https://stackoverflow.com/users/4547691/anatolii-chmykhalo
        """
        san = ''
        ext_count = x509cert.get_extension_count()
        for i in range(0, ext_count):
            ext = x509cert.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                san = ext.__str__()
        # replace commas to not break csv output
        san = san.replace(',', ';')
        return san

    def get_cert_info(self, host, cert):
        """Get all the information about cert and create a JSON file."""
        context = {}

        cert_subject = cert.get_subject()

        context['host'] = host
        context['issued_to'] = cert_subject.CN
        context['issued_o'] = cert_subject.O
        context['issuer_c'] = cert.get_issuer().countryName
        context['issuer_o'] = cert.get_issuer().organizationName
        context['issuer_ou'] = cert.get_issuer().organizationalUnitName
        context['issuer_cn'] = cert.get_issuer().commonName
        context['cert_sn'] = str(cert.get_serial_number())
        context['cert_sha1'] = cert.digest('sha1').decode()
        context['cert_alg'] = cert.get_signature_algorithm().decode()
        context['cert_ver'] = cert.get_version()
        context['cert_sans'] = self.get_cert_sans(cert)
        context['cert_exp'] = cert.has_expired()
        context['cert_valid'] = False if cert.has_expired() else True

        # Valid from
        valid_from = datetime.strptime(cert.get_notBefore().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
        context['valid_from'] = valid_from.strftime('%Y-%m-%d')

        # Valid till
        valid_till = datetime.strptime(cert.get_notAfter().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
        context['valid_till'] = valid_till.strftime('%Y-%m-%d')

        # Validity days
        context['validity_days'] = (valid_till - valid_from).days

        # Validity in days from now
        now = datetime.now()
        context['days_left'] = (valid_till - now).days

        # Valid days left
        context['valid_days_to_expire'] = (datetime.strptime(context['valid_till'],
                                           '%Y-%m-%d') - datetime.now()).days

        if cert.has_expired():
            self.total_expired += 1
        else:
            self.total_valid += 1

        # If the certificate has less than 15 days validity
        if context['valid_days_to_expire'] <= 15:
            self.total_warning += 1

        return context

    def print_status(self, host, context, analyze=False):
        """Print all the usefull info about host."""
        print('\t{}[+]{} {}\n\t{}'.format(Clr.GREEN, Clr.RST, host, '-' * (len(host) + 5)))
        print('\t\tIssued domain: {}'.format(context[host]['issued_to']))
        print('\t\tIssued to: {}'.format(context[host]['issued_o']))
        print('\t\tIssued by: {} ({})'.format(context[host]['issuer_o'], context[host]['issuer_c']))
        print('\t\tValid from: {}'.format(context[host]['valid_from']))
        print('\t\tValid to: {} ({} days left)'.format(context[host]['valid_till'], context[host]['valid_days_to_expire']))
        print('\t\tValidity days: {}'.format(context[host]['validity_days']))
        print('\t\tCertificate valid: {}'.format(context[host]['cert_valid']))
        print('\t\tCertificate S/N: {}'.format(context[host]['cert_sn']))
        print('\t\tCertificate SHA1 FP: {}'.format(context[host]['cert_sha1']))
        print('\t\tCertificate version: {}'.format(context[host]['cert_ver']))
        print('\t\tCertificate algorithm: {}'.format(context[host]['cert_alg']))



        for san in context[host]['cert_sans'].split(';'):
            print('\t\t \\_ {}'.format(san.strip()))

        print('\n')

    def show_result(self, hosts):
        """Get the context."""
        context = {}
        start_time = datetime.now()
        hosts = hosts
        host, port = self.filter_hostname(hosts)


        try:
            cert = self.get_cert(host, port)
            context[host] = self.get_cert_info(host, cert)
            context[host]['tcp_port'] = int(port)
            return context[host]['issued_to'], context[host]['issued_o'],context[host]['issuer_o'],context[host]['cert_valid']
        except:
            print("ssl not found")
            return {}



    def filter_hostname(self, host):
        """Remove unused characters and split by address and port."""
        host = host.replace('http://', '').replace('https://', '').replace('/', '')
        port = 443
        if ':' in host:
            host, port = host.split(':')

        return host, port



"""if __name__ == '__main__':
    SSLCheckerObject = SSLChecker()
    SSLCheckerObject.show_result("www.facebook.com")"""
