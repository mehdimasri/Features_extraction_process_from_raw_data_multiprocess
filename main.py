import whois
from url_based_features import url_based_features
from domain_based_features import domain_based
from html_based_features import html_based
from page_features import page_features
import pandas as pd
import time
import multiprocessing
all_in = []
start  = time.time()
#it is recommended that the url be in a standard format
df = pd.read_csv('top10M.csv',names=["Rank","Domain","Open Page Rank"])
urls = list(df['Domain'])
for URL in urls:

    print(URL.lower())

    # initializing the url based features
    a = url_based_features(URL.lower())

    IP,url_length,shortened,redirect,at,sufi_pref,dot,https = a.result_url()
    print(" Ip =",IP,"\n","@= ",at,"\n","dot =",dot,"\n","https token =",
          https,"\n","sufi_pref = ",sufi_pref,"\n","url_length",url_length,"\n",
          "shortened =",shortened,"\n","redirection =",redirect)
    b = domain_based("https://"+URL.lower())

    rank_page,domain_life,abnormal_url,domain_age, dns_record = b.result_domain()

    def html(URL,q):
       c = html_based("https://"+URL)
       q.put(c.results_html())

    def url(URL,q):
        a = url_based_features("https://"+URL)
        q.put(a.result_url())

    q_html = multiprocessing.Queue()
    q_url = multiprocessing.Queue()
    proc_url = multiprocessing.Process(target=url,args=(URL,q_url))
    proc_html = multiprocessing.Process(target=html,args=(URL,q_html))
    proc_html.start()
    proc_url.start()
    proc_url.join()
    proc_html.join()

    favicon,url_of_anchor,confermity,SFH,mailto,forward,on_mouseover,right_click,pop_up,iframe,links_pointing =q_html.get()
    IP,url_length,shortened,redirect,at,sufi_pref,dot,https = q_url.get()



    d = page_features(URL)
    ssl,google_index,page_score,non_standard_port = d.result_page()

print("done")
print('time spent ', time.time()-start)
print("is url abnormal",abnormal_url)
print("domain life",domain_life)
print("domain age",domain_age)
print("ranking",rank_page)
print("google index",google_index)
print("page score",page_score)
print("SSL",ssl)
print("non standard port", non_standard_port)
print("DNS_record",dns_record)
c = html_based(URL.lower())
favicon,url_of_anchor,confermity,SFH,mailto,forwarding,on_mouseover,\
right_click,pop_up,iframe,links_pointing=c.results_html()
print("iframe",iframe)
print("favicon",favicon)
print("confermitry",confermity)
print("mailto = ",mailto)
print("on_mouseOver",on_mouseover)
print("right click",right_click)
print("forwarding", forwarding)
print("SFH",SFH)
print("links",links_pointing)
print("url_anchor",url_of_anchor)
print("popup",pop_up)
final_output = [IP,url_length,shortened,at,redirect,dot,sufi_pref,ssl,
                domain_life,favicon,non_standard_port,https,confermity,
                url_of_anchor,confermity,SFH,mailto,abnormal_url,forwarding,on_mouseover,
                right_click,pop_up,
                iframe,domain_age,dns_record,rank_page,page_score,google_index,links_pointing
                ]
