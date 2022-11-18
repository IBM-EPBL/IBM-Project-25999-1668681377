from urllib.parse import urlparse
from base64 import urlsafe_b64decode, urlsafe_b64encode
import ssl
from tldextract import extract
import socket
import requests
import urllib
import googlesearch
import re
import whois
import regex
import numpy as np
import requests
import lxml
import networkx as nx
import validators
from bs4 import BeautifulSoup


def having_ip(url):
    try:
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)
        if domain == ip:
            return 1
        else:
            return -1
    except socket.gaierror:
        return 0
    except:
        return 1


def url_length(url):
    length = len(url)
    if(length < 54):
        return -1
    elif(54 <= length <= 75):
        return 0
    else:
        return 1


def shortening_service(url):
    try:
        session = requests.Session()
        resp = session.head(url, allow_redirects=True)
        if resp.url != url:
            return 1
        else:
            return -1
    except:
        return 1


def having_at_symbol(url):
    if "@" in url:
        return 1
    else:
        return -1


def double_slash_redirecting(url):
    try:
        double_slash_index = url.rindex("//")
        if double_slash_index > 7:
            return 1
        else:
            return -1
    except:
        return 1


def prefix_suffix(url):
    try:
        domain = urlparse(url).netloc
        if "-" in domain:
            return 1
        else:
            return -1
    except:
        return 1

def having_sub_domain(url):
    try:
        domain = urlparse(url).netloc
        dot_count = domain.count(".")
        if dot_count == 1:
            return -1
        elif dot_count == 2:
            return 0
        else:
            return 1
    except:
        return 1


def sslfinal_state(url):
    try:
        https = urlparse(url).scheme
        if 'https' in https:
            return -1
        else:
            return 1
    except:
        return 1


def domain_registration_length(url):
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)

        domain_creation_date = domain_info.creation_date[0]
        domain_expiration_date = domain_info.expiration_date[0]

        age = (domain_expiration_date - domain_creation_date).days

        if age <= 365:
            return 1
        else:
            return -1
    except:
        return 1


def favicon(url):
    try:
        domain = urlparse(url).netloc
        page = requests.get(url)
        soup = BeautifulSoup(page.text, features="html.parser")

        icon_url = soup.find("link", rel="icon")["href"]
        icon_url_domain = urlparse(icon_url).netloc

        if domain != icon_url_domain:
            return 1
        else:
            return -1
    except requests.exceptions.SSLError:
        return 1
    except:
        return 1


def port(url):
    try:
        port_number = urlparse(url).port
        if port_number is None:
            return -1
        else:
            service = urlparse(url).scheme
            if (service == "ftp" and port_number == 21) or (service == "ssh" and port_number == 22) or (service == "telnet" and port_number == 23) or (service == "http" and port_number == 80) or (service == "https" and port_number == 443) or (service == "smp" and port_number == 445) or (service == "mssql" and port_number == 1433) or (service == "oracle" and port_number == 1521) or (service == "mysql" and port_number == 3306) or (service == "remote desktop" and port_number == 3389):
                return -1
            else:
                return 1
    except:
        return 1


def https_token(url):
    try:
        domain = urlparse(url).hostname
        if "http" in domain:
            return 1
        else:
            return -1
    except:
        return 1


def request_url(url):
    try:
        domain = urlparse(url).hostname
        page = requests.get(url)
        soup = BeautifulSoup(page.text, features="html.parser")

        img_tags = soup.find_all("img")
        video_tags = soup.find_all("video")
        audio_tags = soup.find_all("audio")

        media_domains = [urlparse(media.get("src")).hostname for media in img_tags+video_tags+audio_tags]

        percent_request_url = len([1 for media_domain in media_domains if domain != media_domain or media_domain is None]) * 100 / len(media_domains)

        if percent_request_url < 22:
            return -1
        else:
            return 1
    except requests.exceptions.SSLError:
        return 1
    except:
        return 1


def url_of_anchor(url):
    try:
        domain = urlparse(url).hostname
        page = requests.get(url)
        soup = BeautifulSoup(page.text, features="html.parser")

        anchor_tags = soup.find_all("a")
        anchor_domains = [urlparse(media.get("href")).hostname for media in anchor_tags]

        percent_anchor_url = len([1 for anchor_domain in anchor_domains if domain != anchor_domain or anchor_domain is None]) * 100 / len(
            anchor_domains)

        if percent_anchor_url < 31:
            return -1
        elif 31 <= percent_anchor_url <= 67:
            return 0
        else:
            return 1
    except requests.exceptions.SSLError:
        return 1
    except:
        return 1


def links_in_tags(url):
    try:
        domain = urlparse(url).hostname
        page = requests.get(url)
        soup = BeautifulSoup(page.text, features="html.parser")

        link_tags = soup.find_all("link")

        link_domains = []
        for tag in link_tags:
            link = tag.get("href")
            if link is not None:
                link_domain = urlparse(link).hostname
                if link_domain is not None and validators.url(link_domain) and domain != link_domain:
                    link_domains.append(link_domain)

        percent_tag_url = len(link_domains) * 100 / len(link_tags)

        if percent_tag_url < 17:
            return -1
        elif 17 <= percent_tag_url <= 81:
            return 0
        else:
            return 1
    except:
        return 1


def sfh(url):
    try:
        domain = urlparse(url).hostname
        page = requests.get(url)
        soup = BeautifulSoup(page.text, features="html.parser")

        form_tags = soup.find_all("form")
        if form_tags == []:
            return -1
        for tag in form_tags:
            tag_url = tag.get("action")
            if tag_url is None:
                return 1
            if tag_url == "":
                return 1
            elif tag_url[0] == "/":
                return -1
            elif urlparse(tag_url).hostname != domain:
                return 0
            else:
                return -1
    except requests.exceptions.SSLError:
        return 1
    except:
        return 1


def submitting_to_email(url):
    try:
        page = requests.get(url)
        soup = BeautifulSoup(page.text, features="html.parser")

        form_tags = soup.find_all("form")

        for tag in form_tags:
            tag_url = tag.get("action")
            if "mailto:" in tag_url or "mail" in tag_url:
                return 1
        return -1
    except requests.exceptions.SSLError:
        return 1
    except:
        return 1


def abnormal_url(url):
    try:
        hostname = urlparse(url).hostname
        whois_object = whois.whois(hostname)

        if whois_object.get("registrar") != "null":
            return -1
        else:
            return 1
    except whois.parser.PywhoisError:
        return 1
    except:
        return 1


def redirect(url):
    try:
        redirect_count = len(requests.get(url).history)

        if redirect_count <= 1:
            return -1
        elif 2 <= redirect_count < 4:
            return 0
        else:
            return 1
    except:
        return 1


def on_mouseover(url):
    try:
        page = requests.get(url)
        soup = BeautifulSoup(page.text, features="html.parser")

        anchor_tags = soup.find_all("a")

        for tag in anchor_tags:
            if tag.get("onmouseover") is not None:
                return 1
        return -1
    except requests.exceptions.SSLError:
        return 1
    except:
        return 1


def rightclick(url):
    try:
        page = requests.get(url)
        soup = BeautifulSoup(page.content, "html.parser")
        html_url = str(soup.find("html"))
        out = re.search("event.button==2", html_url)
        if out is not None:
            return 1
        else:
            return -1
    except requests.exceptions.SSLError:
        return 1
    except:
        return 1


def popupwindow(url):
    try:
        page = requests.get(url)
        soup = BeautifulSoup(page.content, "html.parser")

        scripts = soup.find_all("script")

        for script in scripts:
            content = script.text
            if "prompt" in content:
                return 1
        return -1
    except requests.exceptions.SSLError:
        return 1
    except:
        return 1


def iframe(url):
    try:
        page = requests.get(url)
        soup = BeautifulSoup(page.content, "html.parser")

        iframe = soup.find("iframe")

        if iframe is None:
            return -1
        else:
            return 1
    except requests.exceptions.SSLError:
        return 1
    except:
        return 1


def age_of_domain(url):
    try:
        domain = urlparse(url).hostname
        domain_info = whois.whois(domain)

        domain_creation_date = domain_info.creation_date[0]
        domain_expiration_date = domain_info.expiration_date[0]

        age = (domain_expiration_date - domain_creation_date).days

        if age >= 183:
            return -1
        else:
            return 1
    except:
        return 1


def dnsrecord(url):
    try:
        domain = urlparse(url).hostname
        domain_info = whois.whois(domain)

        if domain_info.get("dnssec") is None:
            return 1
        else:
            return -1
    except whois.parser.PywhoisError:
        return 1
    except:
        return 1


def web_traffic(url):
    try:
        page = requests.get("http://data.alexa.com/data?cli=10&dat=s&url=" + url)
        soup = BeautifulSoup(page.content, "html.parser")
        rank = int(soup.find("reach")["rank"])
        if rank < 100000:
            return -1
        elif rank > 100000:
            return 0
        else:
            return 1
    except requests.exceptions.SSLError:
        return 1
    except:
        return 1


def page_rank(url):
    try:
        domain = urlparse(url).hostname
        prank_checker_response = requests.post("https://www.checkPage_Rank.net/index.php", {"name": domain})

        global_rank = int(re.findall(r"Global Rank: ([0-9]+)", prank_checker_response.text)[0])
        if global_rank > 0 and global_rank < 100000:
            return 1
        return -1
    except:
        return 1


def google_index(url):
    try:
        site = googlesearch.search(url, 5)
        if site:
            return -1
        else:
            return 1
    except:
        return 1


def links_pointing_to_page(url):
    try:
        domain = urlparse(url).hostname
        page = requests.get(url)
        soup = BeautifulSoup(page.content, 'html.parser')
        count = 0
        for link in soup.find_all('a'):
            link_url = link.get("href")
            link_domain = urlparse(link_url).hostname
            if link_domain == domain:
                count += 1
        if count == 0:
            return 1
        if 0 < count <= 2:
            return 0
        else:
            return -1
    except:
        return 1


def statistical_report(url):
    try:
        domain = urlparse(url).hostname
        url_match = re.search(
            'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',
            urlsafe_b64encode)
        ip_address = socket.gethostbyname(domain)
        ip_match = re.search(
            '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
            '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
            '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
            '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
            '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
            '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
            ip_address)
        if url_match or ip_match:
            return 1
        else:
            return -1
    except:
        return 1


def main(url):
    features = [having_ip(url), url_length(url), shortening_service(url), having_at_symbol(url), double_slash_redirecting(url), prefix_suffix(url),
                having_sub_domain(url), sslfinal_state(url), domain_registration_length(url), favicon(url), port(url), https_token(url), request_url(url),
                url_of_anchor(url), links_in_tags(url), sfh(url), submitting_to_email(url), abnormal_url(url), redirect(url), on_mouseover(url),
                rightclick(url), popupwindow(url), iframe(url), age_of_domain(url), dnsrecord(url), web_traffic(url), page_rank(url), google_index(url),
                links_pointing_to_page(url), statistical_report(url)]

    arr = np.array(features).reshape(1, 30)
    return arr


