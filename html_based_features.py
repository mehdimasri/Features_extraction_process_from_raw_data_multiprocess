from bs4 import BeautifulSoup
import requests
import re
from url_based_features import url_based_features

# Initializing
class html_based():
    def __init__(self,URL):
        self.URL = URL

        self.url_features = url_based_features(URL)
        self.page =''
        try:
            headers = {'User-Agent':'Mozila/5.0'}
            self.page =  requests.get(URL, headers=headers,allow_redirects=True,verify=True)
            self.soup = BeautifulSoup(self.page.content, "html.parser")
        except:
            self.soup = "website is down"



# verifies if there is an Iframe balise inside the code
    def iframe(self):
        try:

            result = self.soup.find_all('iframe')
            if result:
                return 1
            else:
                return  -1
        except:
            return 0.001


#checks if favorite icon exists or not
    def favicon(self):
        try:
            result = self.soup.find_all('link')
            soup_rel = []
            #list will possibily contain favicon
            for i in result :
                soup_rel.append(i.get('rel'))
            #iterating throw the list

            for i,row in enumerate(soup_rel):
                if row :
                    if len(row) >1:
                        j = row[0]+" "+row[1]#check for a string composed from two words
                        if re.findall('^shortcut icon$',j):
                            return 1
                    else:
                        if re.findall('^icon$',row[0]):

                            return 1
            return -1
        except:
            return  0.001




# extract URL from the HTML code
    def URL_catcher(self):

        try :
            soup_href = []
            soup_rel = []

            soup_h = self.soup.find_all('a',href=True)
            soup_l = self.soup.find_all('link',href=True)

            for i in soup_l :
                soup_rel.append(i.get('href'))

            for i in soup_h :
                soup_href.append(i.get('href'))

            return soup_href, soup_rel
        except:
            return [],[]


    # are the links in the html conformied to the url
    def links_confermity_to_doamin(self):
        list_of_links_where_domain_exists = []
        list_with_links = []
        if self.url_features.contains_ip():
            return  0.0
        soup_href,soup_rel = self.URL_catcher()


        sub_domain, domain, top_domain = self.url_features.extract_domain(self.URL)

        for i in soup_href+soup_rel:

            #extracting http links
            if re.findall("https*://",str(i)):
                list_with_links.append(str(i))
                _,link_domain,_ = self.url_features.extract_domain(i)#extracting domain from link
                if link_domain == domain:
                    list_of_links_where_domain_exists.append(str(i))

        if len(list_with_links) == 0:
            return -1
        if  (len(list_of_links_where_domain_exists)/len(list_with_links))>0.7:
            return -1
        elif (len(list_of_links_where_domain_exists)/len(list_with_links))>0.4:
            return 0
        else:
            return 1



#mailto indicator
    def mailto(self):
        href,rel =self.URL_catcher()
        for i in href+rel:
            if re.findall("mailto:",i):
                return -1
        return 1




    # Checks the effect of mouse over on status bar (Mouse_Over)
    def mouseOver(self):
      if self.soup == "website is down" :
        return 9999999999
      else:
        if re.findall("<script>.+onmouseover.+</script>", self.soup.text):
          return 1
        else:
          return -1

    # Checks the status of the right click attribute (Right_Click)
    def rightClick(self):
      if self.soup == "website is down":
        return 99999
      else:
        if re.findall(r"event.button ?== ?2", self.soup.text):
          return 1
        else:
          return -1

    # 18.Checks the number of forwardings (Web_Forwards)
    def forwarding(self):

      if self.soup == "website is down":
        return 9999
      else:
        if len(self.page.history) <= 2:
          return 0
        else:
          return 1



    # 16. SFH
    def SFH(self):
        _,domain,_ = self.url_features.extract_domain(self.URL)
        if self.soup == "website is down":

            return 9999999999999
        if len(self.soup.find_all('form', action=True))==0:
            return 1
        else :
            for form in self.soup.find_all('form', action=True):
                if form['action'] == "" or form['action'] == "about:blank":
                    return -1
                    break
                elif self.URL not in form['action'] and domain not in form['action']:
                    return 0
                else:
                    return 1



    def popupwindow(self):

        if self.soup == "website is down":
            return 1
        else:
            if re.findall(r"open\(", self.soup.text):
                return 1
            else:
                return -1

 #url must end with tld
    def number_of_links_pointing_to_page(self):
        a,b = self.URL_catcher()
        #remùoving https/http and directory
        if re.findall("://",self.URL):
            sub_domain_and_top_domain = self.URL.split("//")[-1].split('/')[0]#split https ou domain
            prot = self.URL.split("//")[0]
        else:
            sub_domain_and_top_domain = self.URL.split('/')[0]
        number = 0
        for i in a+b:
            if re.findall(prot+"//"+sub_domain_and_top_domain+"/"+"$",i):
                number = number +1
        if number >2 :
            return -1
        elif number >0:
            return 0
        else:
            return 1




    def URL_of_Anchor(self):
        percentage = 0
        i = 0
        unsafe = 0
        if self.soup == "website is down":
            return 1



        else:
            a,b = self.URL_catcher()
            for j in a+b:
                # 2nd condition was 'JavaScript ::void(0)' but we put JavaScript because the space between javascript and :: might not be
                    # there in the actual a['href']
                if re.findall("^#",j) or re.findall("^javascript.*void(0)",j.lower()):
                    unsafe = unsafe + 1
                i = i + 1

            try:
                percentage = unsafe / float(i) * 100
            except:

                return 1

            if percentage < 31.0:
                return -1
            elif ((percentage >= 31.0) and (percentage < 67.0)):
                return 0
            else:
                return 1

    def results_html(self):
        favicon =self.favicon()
        url_of_anchor = self.URL_of_Anchor()
        confermity = self.links_confermity_to_doamin()
        SFH = self.SFH()
        mailto = self.mailto()
        forward = self.forwarding()
        on_mouseover = self.mouseOver()
        right_click = self.rightClick()
        pop_up = self.popupwindow()
        iframe = self.iframe()
        links_pointing =self.number_of_links_pointing_to_page()

        return favicon,url_of_anchor,confermity,SFH,mailto,forward,on_mouseover,right_click,pop_up,iframe,links_pointing

