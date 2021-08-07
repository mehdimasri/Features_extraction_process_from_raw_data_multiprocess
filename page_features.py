from url_based_features import url_based_features
from ssl_checker import SSLChecker
import re
import socket
from contextlib import closing
import requests
from bs4 import BeautifulSoup
from googlesearch import search
import multiprocessing

dictt = []
class page_features():

    def __init__(self,URL):
        self.URL = URL
        self.url_features = url_based_features(URL)
        self.dict = []


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




    #verifying the ssl certificate function must start with http
    def ssl_verification(self):
        try:
          SSLCheckerObject = SSLChecker()
          if self.url_features.contains_ip()==1:
              return 1
            #remùoving https/http and directory
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

    def proc_google(self,queue):
        queue.put(self.google_index())
        #print("process_google")

    def proc_score(self,queue):
        queue.put(self.page_score())
        #print("process_score")

    def proc_ssl(self,queue):
        queue.put(self.ssl_verification())
        #print("process ssl")

    def proc_port(self):
        self.dict.append(self.non_standard_port())
        #print('proc_port',)

    def result_page(self):
        processes = []
        q_ssl = multiprocessing.Queue()
        q_index = multiprocessing.Queue()
        q_score = multiprocessing.Queue()



        p_google_index = multiprocessing.Process(target=self.proc_google,args=(q_index,))
        #p_port = multiprocessing.Process(target=self.proc_port)
        p_ssl = multiprocessing.Process(target=self.proc_ssl,args=(q_ssl,))
        p_score = multiprocessing.Process(target=self.proc_score,args=(q_score,))
        processes.append(p_google_index)
        #processes.append(p_port)
        processes.append(p_ssl)
        processes.append(p_score)

        p_google_index.start()
        #p_port.start()
        p_ssl.start()
        p_score.start()


        for process in processes:
            process.join()

        return q_ssl.get(),q_index.get(),q_score.get(),4

