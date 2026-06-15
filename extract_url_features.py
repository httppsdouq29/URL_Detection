
"""
Script trích xuất đặc trưng từ URL dựa trên final_dataset.csv
Tạo file CSV chứa các đặc trưng và label (không bao gồm cột URL)
"""

import pandas as pd
import re
import os
import ipaddress
from urllib.parse import urlparse

# Danh sách từ khóa phishing
PHISHING_KEYWORDS = [
    # Authentication & Account (Rất phổ biến trong phishing)
    'login', 'signin', 'weblogin', 'servicelogin', 'loginform', 'logon',
    'account', 'accounts', 'myaccount', 'userid',
    'secure', 'security', 'auth', 'session',
    'verify', 'verification', 'confirm', 'update',
    'password', 'reset', 'unlock', 'authenticate',
    
    # Payment & Banking (Thường bị giả mạo)
    'paypal', 'webscr', 'payment', 'billing', 'invoice',
    'refund', 'wallet', 'card', 'credit', 'debit',
    'chase', 'wellsfargo', 'bank',
    
    # Brand Names (Thường bị giả mạo)
    'google', 'dropbox', 'adobe', 'aol', 'outlook',
    'microsoft', 'apple', 'facebook', 'instagram',
    'dhl', 'alibaba',
    
    # Suspicious Patterns
    'admin', 'administrator', 'cmd', 'dispatch',
    'submit', 'form', 'forms', 'upload', 'uploads',
    'file', 'files', 'document', 'docs',
    'webmail', 'email', 'mail',
    'link', 'links', 'url',
    
    # Suspicious Domains & Services
    'ipfs', 'firebaseapp', 'weeblysite', 'wixsite',
    'godaddysites', 'pantheonsite', 'webwave',
    '000webhostapp', 'appspot', 'duckdns', 'tinyurl',
    'pastehtml', 'repl', 'cloudflare',
    
    # Technical Suspicious Terms
    'wp', 'web', 'app', 'apps', 'webapps',
    'content', 'includes', 'plugins', 'themes',
    'modules', 'mod', 'components', 'templates',
    'assets', 'libraries', 'cache',
    'bin', 'dev', 'test', 'tmp',
    
    # Suspicious Actions
    'update', 'upgrade', 'access', 'panel',
    'gate', 'system', 'network', 'service',
    'processing', 'run', 'start',
    
    # Suspicious Parameters & Values
    'ref', 'rand', 'fid', 'amp', 'false', 'true',
    'loop', 'delayms', 'att', 'pp', 'fb',
    'ip', 'ssl', 'cloud', 'drive',
    
    # Country codes thường dùng trong phishing (nhưng cần kết hợp với yếu tố khác)
    'ru', 'io', 'xyz', 'tk', 'ml', 'gq', 'cf',
    
    # Other suspicious patterns
    'presentation', 'bookmark', 'log', 'logs',
    'error', 'share', 'sharepoint', 'client',
    'express', 'support', 'help', 'information',
    'personal', 'customer', 'user', 'users',
    'data', 'source', 'image', 'images', 'img',
    'site', 'sites', 'top', 'online',
    'my', 'me', 'eu', 'ro', 'cl', 'mx', 'ga', 'ws',
    'cc', 'ch', 'cz', 'ar', 'dk', 'tr', 'za', 'ua',
    'ir', 'vn', 'hu', 'pt', 'lg', 'ly', 'ai',
    
    # Very specific phishing patterns
    '13inboxlight', '2pacx', 'aspxn', 'cmnd',
    'attachauth', 'jehfuq', 'vjoxk0qwhtogydw',
    'amp;fid', 'amp;fav', 'amp;delayms', 'amp;loop',
    'amp;app', 'amp;id', 'amp;rand', 'amp;dispatch',
    'amp;session', 'amp;email', 'amp;attredirects',
    'stickamcomlogindo', 'xsph', 'dweb',
    'battle', 'runescape', 'remax', 'ii',
    'eth', 'r2', 'd3', 'gd', 'nav', 'ap',
]

special_chars = set('!@#$%^&*(),.?":{}|<>_=+-')

redirect_terms = ['redirect', 'url', 'link', 'goto', 'forward']

ref_terms = ['ref=', 'cdm=', 'referrer=', 'reference=', 'aff=']

http_terms = ['http', 'https', 'www']

vowels = set('aeiouAEIOU')

split_pattern = re.compile(r'[\/\?&=:#]')

hex_pattern = re.compile(r'%[0-9a-fA-F]{2}')

scheme_pattern = re.compile(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://')


def normalize_url(value):
    """Chuẩn hóa URL"""
    if pd.isna(value):
        return ''
    return str(value).strip()


def wrap_ipv6_host(candidate):
    """Bọc IPv6 host trong dấu ngoặc vuông nếu cần"""
    if '://' not in candidate:
        return candidate
    scheme, rest = candidate.split('://', 1)
    authority, sep, remainder = rest.partition('/')
    if authority.startswith('[') or ']' in authority:
        return candidate
    userinfo, at, host_port = authority.rpartition('@')
    target = host_port if at else authority
    if ':' not in target:
        return candidate
    host_part = target
    port_suffix = ''
    if target.count(':') > 1 and target.rfind(':') != -1:
        potential_host, _, potential_port = target.rpartition(':')
        if potential_port.isdigit():
            host_part = potential_host
            port_suffix = f":{potential_port}"
    wrapped = f"[{host_part}]{port_suffix}"
    if at:
        authority = f"{userinfo}@{wrapped}"
    else:
        authority = wrapped
    rebuilt = f"{scheme}://{authority}"
    if sep:
        rebuilt += '/' + remainder
    return rebuilt


def parse_url(value):
    """Parse URL với xử lý IPv6"""
    if not value:
        return urlparse('')
    candidate = value if scheme_pattern.match(value) else 'http://' + value
    try:
        return urlparse(candidate)
    except ValueError:
        wrapped = wrap_ipv6_host(candidate)
        try:
            return urlparse(wrapped)
        except ValueError:
            return urlparse('')


def get_netloc(parsed):
    """Lấy netloc từ parsed URL"""
    netloc = parsed.netloc or parsed.path.split('/')[0]
    return netloc.split('@')[-1]


def get_host_parts(netloc):
    """Tách host thành base và clean"""
    if netloc.startswith('[') and netloc.endswith(']'):
        return netloc, netloc[1:-1]
    parts = netloc.split(':')
    return netloc, parts[0] if parts else ''


def url_length(url):
    """Độ dài của URL"""
    return len(url)


def count_special_chars(url):
    """Đếm số lượng ký tự đặc biệt"""
    return sum(1 for c in url if c in special_chars)


def has_keyword(url_lower):
    """Kiểm tra URL có chứa từ khóa phishing hay không"""
    return 1 if any(keyword in url_lower for keyword in PHISHING_KEYWORDS) else 0


def has_special_char(special_count):
    """Kiểm tra URL có chứa ký tự đặc biệt hay không"""
    return 1 if special_count > 0 else 0


def count_hex_chars(url):
    """Đếm số lượng ký tự hexa (%XX)"""
    return len(hex_pattern.findall(url))


def count_digits(url):
    """Đếm số lượng chữ số"""
    return sum(1 for c in url if c.isdigit())


def count_dots(url):
    """Đếm số lượng dấu chấm"""
    return url.count('.')


def count_slashes(url):
    """Đếm số lượng dấu gạch chéo"""
    return url.count('/')


def slash_ratio(url):
    """Tỉ lệ số dấu gạch chéo (/) so với độ dài URL"""
    url_len = len(url)
    if url_len == 0:
        return 0.0
    return count_slashes(url) / url_len


def count_uppercase(url):
    """Đếm số lượng chữ cái in hoa"""
    return sum(1 for c in url if c.isupper())


def count_vowels(url):
    """Đếm số lượng nguyên âm (a, e, i, o, u, cả hoa và thường)"""
    return sum(1 for c in url if c.lower() in vowels)


def count_consonants(url):
    """Đếm số lượng phụ âm"""
    return sum(1 for c in url if c.isalpha() and c.lower() not in vowels)


def domain_to_url_ratio(url, parsed):
    """Tỉ lệ độ dài domain so với độ dài toàn bộ URL"""
    url_len = len(url)
    if url_len == 0:
        return 0.0
    netloc = get_netloc(parsed)
    domain_base, domain_clean = get_host_parts(netloc)
    domain_len = len(domain_clean)
    return domain_len / url_len if url_len > 0 else 0.0


def has_http_www(url_lower):
    """Kiểm tra URL có chứa http, https, hoặc www hay không"""
    return 1 if any(term in url_lower for term in http_terms) else 0


def has_ip(host):
    """Kiểm tra URL có chứa địa chỉ IP (IPv4 hoặc IPv6) hay không"""
    try:
        ipaddress.ip_address(host)
        return 1
    except:
        return 0


def has_exe(url_lower):
    """Kiểm tra URL có chứa đuôi .exe hay không"""
    return 1 if '.exe' in url_lower else 0


def has_port(parsed):
    """Kiểm tra URL có chứa cổng (port) hay không"""
    try:
        return 1 if parsed.port is not None else 0
    except:
        return 0


def has_backslash(url):
    """Kiểm tra URL có chứa dấu \ hay không"""
    return 1 if '\\' in url else 0


def has_redirect(url_lower):
    """Kiểm tra URL có chứa tham số chuyển hướng hay không"""
    return 1 if any(term in url_lower for term in redirect_terms) else 0


def has_ref(url_lower):
    """Kiểm tra URL có chứa tham số ref=, cdm=, referrer=, reference=, hoặc aff= hay không"""
    return 1 if any(term in url_lower for term in ref_terms) else 0


def max_sub30(url):
    """Kiểm tra chuỗi con lớn nhất trong URL (phân tách bởi /?&=:#) có độ dài > 30 ký tự hay không"""
    parts = split_pattern.split(url)
    longest = max((len(part) for part in parts if part), default=0)
    return 1 if longest > 30 else 0


def extract_features(url):
    """
    Trích xuất tất cả các đặc trưng từ URL
    
    Returns:
        Dictionary chứa các đặc trưng
    """
    normalized = normalize_url(url)
    parsed = parse_url(normalized)
    netloc = get_netloc(parsed)
    domain_base, domain_clean = get_host_parts(netloc)
    url_lower = normalized.lower()
    special_count = count_special_chars(normalized)
    
    features = {
        'urlLength': url_length(normalized),
        'specialCharsCount': special_count,
        'hasKeyword': has_keyword(url_lower),
        'hasSpecialChar': has_special_char(special_count),
        'hexCharsCount': count_hex_chars(normalized),
        'digitsCount': count_digits(normalized),
        'dotCount': count_dots(normalized),
        'slashRatio': slash_ratio(normalized),
        'uppercaseCount': count_uppercase(normalized),
        'vowelsCount': count_vowels(normalized),
        'consonantsCount': count_consonants(normalized),
        'domainToUrlRatio': domain_to_url_ratio(normalized, parsed),
        'hasHttpWww': has_http_www(url_lower),
        'hasIp': has_ip(domain_clean),
        'hasExe': has_exe(url_lower),
        'hasPort': has_port(parsed),
        'hasBackslash': has_backslash(normalized),
        'hasRedirect': has_redirect(url_lower),
        'hasRef': has_ref(url_lower),
        'maxSub30': max_sub30(normalized),
    }
    
    return features


def main():
    """Hàm chính để xử lý dữ liệu"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    input_path = os.path.join(base_dir, 'final_csv', 'final_dataset.csv')
    output_path = os.path.join(base_dir, 'final_csv', 'url_features_extracted.csv')
    
    print(f"Đang đọc dữ liệu từ: {input_path}")
    df = pd.read_csv(input_path)
    
    print(f"Tổng số URL: {len(df)}")
    print("Đang trích xuất đặc trưng...")
    
    # Sử dụng apply để tối ưu hiệu suất
    def process_with_progress(series):
        """Wrapper để hiển thị tiến trình"""
        total = len(series)
        results = []
        for idx, url in enumerate(series):
            if (idx + 1) % 10000 == 0:
                print(f"Đã xử lý: {idx + 1}/{total} ({100*(idx+1)/total:.1f}%)")
            results.append(extract_features(url))
        return results
    
    # Trích xuất đặc trưng
    features_list = process_with_progress(df['url'])
    
    # Tạo DataFrame từ danh sách đặc trưng
    features_df = pd.DataFrame(features_list)
    
    # Thêm label (không thêm URL)
    if 'label' in df.columns:
        features_df['label'] = df['label']
    
    # Lưu file CSV (không có cột URL)
    print(f"Đang lưu kết quả vào: {output_path}")
    features_df.to_csv(output_path, index=False)
    
    print(f"Hoàn thành! Đã tạo file với {len(features_df)} dòng và {len(features_df.columns)} cột")
    print(f"Các cột: {list(features_df.columns)}")
    print(f"\nThống kê:")
    print(features_df.describe())


if __name__ == '__main__':
    main()

