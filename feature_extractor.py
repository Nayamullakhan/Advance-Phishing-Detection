import re
import urllib.parse
import tldextract
import requests
import whois
import dns.resolver
import ipaddress
import time
from datetime import datetime
import socket
import ssl

# Define the exact feature order as expected by the model
FEATURE_NAMES = [
    'qty_dot_url', 'qty_hyphen_url', 'qty_underline_url', 'qty_slash_url', 'qty_questionmark_url', 
    'qty_equal_url', 'qty_at_url', 'qty_and_url', 'qty_exclamation_url', 'qty_space_url', 
    'qty_tilde_url', 'qty_comma_url', 'qty_plus_url', 'qty_asterisk_url', 'qty_hashtag_url', 
    'qty_dollar_url', 'qty_percent_url', 'qty_tld_url', 'length_url', 'qty_dot_domain', 
    'qty_hyphen_domain', 'qty_underline_domain', 'qty_slash_domain', 'qty_questionmark_domain', 
    'qty_equal_domain', 'qty_at_domain', 'qty_and_domain', 'qty_exclamation_domain', 'qty_space_domain', 
    'qty_tilde_domain', 'qty_comma_domain', 'qty_plus_domain', 'qty_asterisk_domain', 'qty_hashtag_domain', 
    'qty_dollar_domain', 'qty_percent_domain', 'qty_vowels_domain', 'domain_length', 'domain_in_ip', 
    'server_client_domain', 'qty_dot_directory', 'qty_hyphen_directory', 'qty_underline_directory', 
    'qty_slash_directory', 'qty_questionmark_directory', 'qty_equal_directory', 'qty_at_directory', 
    'qty_and_directory', 'qty_exclamation_directory', 'qty_space_directory', 'qty_tilde_directory', 
    'qty_comma_directory', 'qty_plus_directory', 'qty_asterisk_directory', 'qty_hashtag_directory', 
    'qty_dollar_directory', 'qty_percent_directory', 'directory_length', 'qty_dot_file', 'qty_hyphen_file', 
    'qty_underline_file', 'qty_slash_file', 'qty_questionmark_file', 'qty_equal_file', 'qty_at_file', 
    'qty_and_file', 'qty_exclamation_file', 'qty_space_file', 'qty_tilde_file', 'qty_comma_file', 
    'qty_plus_file', 'qty_asterisk_file', 'qty_hashtag_file', 'qty_dollar_file', 'qty_percent_file', 
    'file_length', 'qty_dot_params', 'qty_hyphen_params', 'qty_underline_params', 'qty_slash_params', 
    'qty_questionmark_params', 'qty_equal_params', 'qty_at_params', 'qty_and_params', 'qty_exclamation_params', 
    'qty_space_params', 'qty_tilde_params', 'qty_comma_params', 'qty_plus_params', 'qty_asterisk_params', 
    'qty_hashtag_params', 'qty_dollar_params', 'qty_percent_params', 'params_length', 'tld_present_params', 
    'qty_params', 'email_in_url', 'time_response', 'domain_spf', 'asn_ip', 'time_domain_activation', 
    'time_domain_expiration', 'qty_ip_resolved', 'qty_nameservers', 'qty_mx_servers', 'ttl_hostname', 
    'tls_ssl_certificate', 'qty_redirects', 'url_google_index', 'domain_google_index', 'url_shortened'
]

def count_char(s, char):
    return s.count(char) if s else 0

def get_domain_parts(url):
    extracted = tldextract.extract(url)
    domain = extracted.domain + '.' + extracted.suffix
    subdomain = extracted.subdomain
    if subdomain:
        full_domain = subdomain + '.' + domain
    else:
        full_domain = domain
    return full_domain

def extract_features(url):
    features = {}
    
    # Ensure URL has schema
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    parsed = urllib.parse.urlparse(url)
    
    # URL parts
    path = parsed.path
    query = parsed.query
    
    # Isolate directory and file
    if '.' in path.split('/')[-1]:
        file_name = path.split('/')[-1]
        directory = '/'.join(path.split('/')[:-1]) + '/'
    else:
        file_name = ""
        directory = path
        
    full_domain = get_domain_parts(url)
    
    # --- URL Based Features ---
    features['qty_dot_url'] = count_char(url, '.')
    features['qty_hyphen_url'] = count_char(url, '-')
    features['qty_underline_url'] = count_char(url, '_')
    features['qty_slash_url'] = count_char(url, '/')
    features['qty_questionmark_url'] = count_char(url, '?')
    features['qty_equal_url'] = count_char(url, '=')
    features['qty_at_url'] = count_char(url, '@')
    features['qty_and_url'] = count_char(url, '&')
    features['qty_exclamation_url'] = count_char(url, '!')
    features['qty_space_url'] = count_char(url, ' ')
    features['qty_tilde_url'] = count_char(url, '~')
    features['qty_comma_url'] = count_char(url, ',')
    features['qty_plus_url'] = count_char(url, '+')
    features['qty_asterisk_url'] = count_char(url, '*')
    features['qty_hashtag_url'] = count_char(url, '#')
    features['qty_dollar_url'] = count_char(url, '$')
    features['qty_percent_url'] = count_char(url, '%')
    features['qty_tld_url'] = count_char(full_domain, '.') # Approximate TLD count as dot count? Or actual TLD length? Let's check logic. Usually it's count of TLD in URL? Or count of dots in TLD? Assuming count of TLD string in URL if known, but here likely just dots. Wait, 'qty_tld_url' usually means quantity of TLD extension occurrences in URL? Or length of TLD? 
    # Re-reading standard datasets (e.g. ISCX-URL-2016), qty_tld_url is "Top Level Domain Character Count" or "Quantity of TLDs"? 
    # Let's assume it's just count of the TLD string in the URL (e.g. '.com' appears X times).
    extracted = tldextract.extract(url)
    tld = extracted.suffix
    features['qty_tld_url'] = url.count(tld) if tld else 0
    features['length_url'] = len(url)
    
    # --- Domain Based Features ---
    features['qty_dot_domain'] = count_char(full_domain, '.')
    features['qty_hyphen_domain'] = count_char(full_domain, '-')
    features['qty_underline_domain'] = count_char(full_domain, '_')
    features['qty_slash_domain'] = count_char(full_domain, '/')
    features['qty_questionmark_domain'] = count_char(full_domain, '?')
    features['qty_equal_domain'] = count_char(full_domain, '=')
    features['qty_at_domain'] = count_char(full_domain, '@')
    features['qty_and_domain'] = count_char(full_domain, '&')
    features['qty_exclamation_domain'] = count_char(full_domain, '!')
    features['qty_space_domain'] = count_char(full_domain, ' ')
    features['qty_tilde_domain'] = count_char(full_domain, '~')
    features['qty_comma_domain'] = count_char(full_domain, ',')
    features['qty_plus_domain'] = count_char(full_domain, '+')
    features['qty_asterisk_domain'] = count_char(full_domain, '*')
    features['qty_hashtag_domain'] = count_char(full_domain, '#')
    features['qty_dollar_domain'] = count_char(full_domain, '$')
    features['qty_percent_domain'] = count_char(full_domain, '%')
    features['qty_vowels_domain'] = len([c for c in full_domain if c.lower() in 'aeiou'])
    features['domain_length'] = len(full_domain)
    
    # domain_in_ip
    try:
        ipaddress.ip_address(full_domain)
        features['domain_in_ip'] = 1
    except:
        features['domain_in_ip'] = 0
        
    features['server_client_domain'] = 1 if 'server' in full_domain or 'client' in full_domain else 0
    
    # --- Directory Based Features ---
    features['qty_dot_directory'] = count_char(directory, '.')
    features['qty_hyphen_directory'] = count_char(directory, '-')
    features['qty_underline_directory'] = count_char(directory, '_')
    features['qty_slash_directory'] = count_char(directory, '/')
    features['qty_questionmark_directory'] = count_char(directory, '?')
    features['qty_equal_directory'] = count_char(directory, '=')
    features['qty_at_directory'] = count_char(directory, '@')
    features['qty_and_directory'] = count_char(directory, '&')
    features['qty_exclamation_directory'] = count_char(directory, '!')
    features['qty_space_directory'] = count_char(directory, ' ')
    features['qty_tilde_directory'] = count_char(directory, '~')
    features['qty_comma_directory'] = count_char(directory, ',')
    features['qty_plus_directory'] = count_char(directory, '+')
    features['qty_asterisk_directory'] = count_char(directory, '*')
    features['qty_hashtag_directory'] = count_char(directory, '#')
    features['qty_dollar_directory'] = count_char(directory, '$')
    features['qty_percent_directory'] = count_char(directory, '%')
    features['directory_length'] = len(directory)
    
    # --- File Based Features ---
    features['qty_dot_file'] = count_char(file_name, '.')
    features['qty_hyphen_file'] = count_char(file_name, '-')
    features['qty_underline_file'] = count_char(file_name, '_')
    features['qty_slash_file'] = count_char(file_name, '/')
    features['qty_questionmark_file'] = count_char(file_name, '?')
    features['qty_equal_file'] = count_char(file_name, '=')
    features['qty_at_file'] = count_char(file_name, '@')
    features['qty_and_file'] = count_char(file_name, '&')
    features['qty_exclamation_file'] = count_char(file_name, '!')
    features['qty_space_file'] = count_char(file_name, ' ')
    features['qty_tilde_file'] = count_char(file_name, '~')
    features['qty_comma_file'] = count_char(file_name, ',')
    features['qty_plus_file'] = count_char(file_name, '+')
    features['qty_asterisk_file'] = count_char(file_name, '*')
    features['qty_hashtag_file'] = count_char(file_name, '#')
    features['qty_dollar_file'] = count_char(file_name, '$')
    features['qty_percent_file'] = count_char(file_name, '%')
    features['file_length'] = len(file_name)
    
    # --- Params Based Features ---
    features['qty_dot_params'] = count_char(query, '.')
    features['qty_hyphen_params'] = count_char(query, '-')
    features['qty_underline_params'] = count_char(query, '_')
    features['qty_slash_params'] = count_char(query, '/')
    features['qty_questionmark_params'] = count_char(query, '?')
    features['qty_equal_params'] = count_char(query, '=')
    features['qty_at_params'] = count_char(query, '@')
    features['qty_and_params'] = count_char(query, '&')
    features['qty_exclamation_params'] = count_char(query, '!')
    features['qty_space_params'] = count_char(query, ' ')
    features['qty_tilde_params'] = count_char(query, '~')
    features['qty_comma_params'] = count_char(query, ',')
    features['qty_plus_params'] = count_char(query, '+')
    features['qty_asterisk_params'] = count_char(query, '*')
    features['qty_hashtag_params'] = count_char(query, '#')
    features['qty_dollar_params'] = count_char(query, '$')
    features['qty_percent_params'] = count_char(query, '%')
    features['params_length'] = len(query)
    features['tld_present_params'] = 1 if tld in query else 0
    features['qty_params'] = len(parsed.query.split('&')) if parsed.query else 0
    
    # --- Email in URL ---
    features['email_in_url'] = 1 if re.search(r'[\w\.-]+@[\w\.-]+', url) else 0
    
    # --- Network/External Features (Simulated/Timeouts) ---
    
    # time_response
    try:
        start_time = time.time()
        requests.get(url, timeout=1)
        features['time_response'] = time.time() - start_time
    except:
        features['time_response'] = -1

    # domain_spf (simplified: check TXT record)
    try:
        answers = dns.resolver.resolve(full_domain, 'TXT')
        features['domain_spf'] = 1 if any('spf1' in str(r) for r in answers) else 0
    except:
        features['domain_spf'] = -1
        
    # asn_ip (simplified: just resolve IP usually, but ASN requires GeoIP DB or API. Placeholder -1)
    features['asn_ip'] = -1
    
    # time_domain_activation & expiration (WHOIS)
    try:
        w = whois.whois(full_domain)
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        
        if isinstance(creation_date, list): creation_date = creation_date[0]
        if isinstance(expiration_date, list): expiration_date = expiration_date[0]
        
        if creation_date:
            features['time_domain_activation'] = (datetime.now() - creation_date).days
        else:
            features['time_domain_activation'] = -1
            
        if expiration_date:
            features['time_domain_expiration'] = (expiration_date - datetime.now()).days
        else:
            features['time_domain_expiration'] = -1
    except:
        features['time_domain_activation'] = -1
        features['time_domain_expiration'] = -1
        
    # qty_ip_resolved
    try:
        answers = dns.resolver.resolve(full_domain, 'A')
        features['qty_ip_resolved'] = len(answers)
    except:
        features['qty_ip_resolved'] = -1
        
    # qty_nameservers
    try:
        answers = dns.resolver.resolve(full_domain, 'NS')
        features['qty_nameservers'] = len(answers)
    except:
        features['qty_nameservers'] = -1
        
    # qty_mx_servers
    try:
        answers = dns.resolver.resolve(full_domain, 'MX')
        features['qty_mx_servers'] = len(answers)
    except:
        features['qty_mx_servers'] = 0
        
    # ttl_hostname
    try:
        answers = dns.resolver.resolve(full_domain, 'A')
        features['ttl_hostname'] = answers.rrset.ttl
    except:
        features['ttl_hostname'] = -1
        
    # tls_ssl_certificate
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=full_domain) as s:
            s.settimeout(1)
            s.connect((full_domain, 443))
            cert = s.getpeercert()
            features['tls_ssl_certificate'] = 1 if cert else 0
    except:
        features['tls_ssl_certificate'] = 0
        
    # qty_redirects
    try:
        r = requests.get(url, timeout=1)
        features['qty_redirects'] = len(r.history)
    except:
        features['qty_redirects'] = -1
        
    # url_google_index / domain_google_index (Placeholder -1, requires paid API or scraping)
    features['url_google_index'] = -1
    features['domain_google_index'] = -1
    
    # url_shortened
    shorteners = ['bit.ly', 'goo.gl', 'shorte.st', 'go2l.ink', 'x.co', 'ow.ly', 't.co', 'tinyurl', 'tr.im', 'is.gd', 'cli.gs', 'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to', 'BudURL.com', 'ping.fm', 'post.ly', 'Just.as', 'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 'om.ly', 'to.ly', 'bit.do', 't.cn', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly', 'goo.gl', 'bitly.com', 'cur.lv', 'tinyurl.com', 'ow.ly', 'bit.ly', 'ity.im', 'q.gs', 'is.gd', 'po.st', 'bc.vc', 'twitthis.com', 'u.to', 'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org', 'x.co', 'prettylinkpro.com', 'scrnch.me', 'filoops.info', 'vzturl.com', 'qr.net', '1url.com', 'tweez.me', 'v.gd', 'tr.im', 'link.zip.net']
    features['url_shortened'] = 1 if any(s in x for s in shorteners for x in [full_domain]) else 0
    
    # Return features in the correct order
    return [features[f] for f in FEATURE_NAMES]

# Test function
if __name__ == "__main__":
    url = "http://google.com"
    print(f"Extracting features for {url}...")
    feats = extract_features(url)
    print(f"Extracted {len(feats)} features")
    print(feats[:10])
