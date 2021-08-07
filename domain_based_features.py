from whois import whois
from datetime import datetime
from url_based_features import url_based_features
from ssl_checker import SSLChecker
import re
import socket
from contextlib import closing
import requests
from bs4 import BeautifulSoup
from googlesearch import search
import multiprocessing


class domain_based():
    def __init__(self,URL):
        self.URL = URL
        self.dict = []
        try:
            self.whois_dict = whois(self.URL)
            #print('hi')
        except:
            self.whois_dict = None
        self.url_features = url_based_features(URL)


    #extracting the domain age in years how long is this domain reserved
    def domain_age(self):
      try:
        details = self.whois_dict
        expirations = details['expiration_date']
        creations = details['creation_date']
        if expirations == None or creations == None:
          return 0
        if type(expirations) is list:
          expirations = expirations[0]
        if type(creations) is list:
          creations = creations[0]
        if (expirations - creations).days/365.0 >2.0:
            return -1
        return 1
      except:
        return 0.001

#host name with which the domain was registrated
    def abnormal_url(self):
        try:
            details = self.whois_dict
            domains = details['domain_name']

            _,domain_url,_ = self.url_features.extract_domain(self.URL)

            if type(domains) is list:
              domain = domains[0].lower()

              if domain_url == domain.split('.')[0]:
                return -1
              else:
                return 1
            return int(domains.split('.')[0] != domain_url)
        except:
            return  1

#Since who long was the domain created returns in years
    def domain_life(self):
        try:
            details = self.whois_dict
            if details is None:
                return 1
            creations = details['creation_date']

            if creations == None:
              return 1

            if type(creations) is list:
              creations = creations[0]
            if ((datetime.now() - creations).days/365.0>0.5):
                return -1
            return 1
        except:
            return 1

    def trusted_ssl_provider(self,name):
        list_of_trusted = [
            "Symantec"
            "GeoTrust",
            "Comodo",
            "DigiCert",
            "Thawte",
            "GoDaddy",
            "Network Solutions",
            "RapidSSLonline",
            "SSL.com",
            "Entrust Datacard",
            "Google",
            "Google Trust Services",
            "DigiCert Inc",
            "Cloudflare, Inc.",
            'DigiCert, Inc.',
            "Sectigo Limited",
            "Let's Encrypt",
            "GlobalSign nv-sa",
            'Microsoft Corporation',
            "HydrantID (Avalanche Cloud Corporation)"
        ]
        if name in list_of_trusted:
            return 1
        else:
            return 0




    #Verifying the ssl certificate function must start with http
    def ssl_verification(self):
        try:
          SSLCheckerObject = SSLChecker()
          if self.url_features.contains_ip()==1:
              return 1
            #removing https/http and directory
          if re.findall("://",self.URL):
            sub_domain_and_top_domain = self.URL.split("//")[-1].split('/')[0]
            protocol =self.URL.split("//")[0]
            #split https ou domain
          else:
            sub_domain_and_top_domain = self.URL.split('/')[0]
            #splitting sub/domain/tld
          URL = protocol+"//"+sub_domain_and_top_domain

          S = SSLCheckerObject.show_result(URL)
          domain = None
          issued_to = None
          authority = None
          valid = None

          if S is not None :
              domain = S[0]
              issued_to = S[1]
              authority = S[2]
              valid = S[3]
          print(S)
          trusted_vendor = self.trusted_ssl_provider(authority)
          if authority and issued_to and ( valid == "True"):

              return trusted_vendor*(-1)

          if valid == False:
              return 1
          if authority is None:
              return 1

          if issued_to is None and trusted_vendor == 1:
              return 0

          if issued_to is None and trusted_vendor == 0:
              return 1

          return trusted_vendor*(-1.0)

        except:
            return 1


# checking for open ports in the website
    def non_standard_port(host):
        list_of_ports_closed = [21,22,23,445,1433,1521,3306,3389]
        list_of_ports_open = [80,443]
        host = host.URL.split("://")[-1].split('/')[0]

        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(3)
            for i in list_of_ports_closed:
                if sock.connect_ex((host, i)) == 0:
                    return 1

            if sock.connect_ex((host, list_of_ports_open[0])) == 0 or sock.connect_ex((host, list_of_ports_open[1])) == 0:
                    return -1
            else:
                    return 1

# The rank of the web page
    def rank_page(URL):
        try:
            headers = {'User-Agent':'Mozila/5.0'}
            page =  requests.get("http://data.alexa.com/data?cli=10&dat=s&url="+URL, headers=headers,allow_redirects=True)
            soup = BeautifulSoup(page.content,"html.parser")
            global_rank= soup.reach['rank']
            rank = int(global_rank)
            if (rank < 100000):
                return -1
            else:
                return 1
        except :
            return 1
# Google index
    def google_index(self):
        try:
            _,domain,tld = self.url_features.extract_domain(self.URL)
            tld_final = ''
            if type(tld) is list:
                tld_final = '.'.join(tld)
            else:
                tld_final = tld
            site = search("site:"+domain+'.'+tld_final)
            if site:
                return -1
            else:
                return 1
        except:
            return -0.00001

# The score assigned by Google
    def page_score(self):
        if re.findall("://",self.URL):
            sub_domain_and_top_domain = self.URL.split("//")[-1].split('/')[0]#split https ou domain
            prot = self.URL.split("//")[0]
        else:
            sub_domain_and_top_domain = self.URL.split('/')[0]
        try:
            headers = {'User-Agent':'Mozila/5.0'}
            headers = {'API-OPR':'gwwkck4sgk0k0cc4s0wgwkwogg4cso8gookoogkk'}
            url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + sub_domain_and_top_domain
            request = requests.get(url, headers=headers)
            result = request.json()
            if (result['response'][0]['page_rank_integer'] > 2):
                return -1
            else:
                return 1
        except:
            return 1


# The DNS record
    def DNS_record(self):
        try:
            details = self.whois_dict
            domains = details['domain_name']
            if domains:
                return -1
            else:
                return 1
        except:
            return 1




    def result_domain(self):
        rank_page = self.rank_page()
        domain_life = self.domain_life()
        abnormal_url = self.abnormal_url()
        domain_age = self.domain_age()
        dns_record =self.DNS_record()
        return rank_page, domain_life,abnormal_url,domain_age,dns_record
