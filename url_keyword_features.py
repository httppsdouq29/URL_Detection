# -*- coding: utf-8 -*-
"""
Danh sách từ khóa để phân tích URL lừa đảo dựa trên phân tích dữ liệu thực tế
Từ khóa được trích xuất từ file tu_pho_bien_tu_url.txt

Sử dụng:
    from url_keyword_features import extract_keyword_features, PHISHING_KEYWORDS, LEGITIMATE_KEYWORDS
    
    features = extract_keyword_features(url)
"""

import re
from typing import Dict, List, Set


# ============================================================================
# DANH SÁCH TỪ KHÓA PHISHING (High Confidence - >= 70% xuất hiện trong URL phishing)
# ============================================================================
PHISHING_KEYWORDS: List[str] = [
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


# ============================================================================
# DANH SÁCH TỪ KHÓA LEGITIMATE (High Confidence - >= 70% xuất hiện trong URL legitimate)
# ============================================================================
LEGITIMATE_KEYWORDS: List[str] = [
    # Educational & Reference
    'wiki', 'wikipedia', 'wikia',
    'ietf', 'archive', 'answers',
    
    # News & Media
    'news', 'watch', 'video', 'videos',
    'youtube', 'movies', 'movie', 'films', 'film',
    'music', 'lyrics', 'album', 'artist',
    'tv', 'sports', 'football', 'basketball', 'baseball',
    'nhl', 'season', 'player', 'players', 'team',
    
    # Social & Professional Networks
    'facebook', 'linkedin', 'myspace', 'mylife',
    'people', 'profile', 'profiles',
    
    # E-commerce & Business
    'amazon', 'yahoo', 'blogspot',
    'products', 'product', 'review', 'reviews',
    'company', 'companies', 'directory',
    
    # Content & Articles
    'article', 'articles', 'story', 'stories',
    'topic', 'topics', 'category', 'categories',
    'blog', 'blogs',
    
    # Search & Information
    'search', 'about', 'tools',
    'information', 'history', 'genealogy', 'ancestry',
    
    # Location-based
    'city', 'cities', 'montreal', 'kansas', 'oakland',
    'quebec', 'canada', 'state', 'states',
    'world', 'all',
    
    # General Content
    'page', 'pages', 'home', 'view',
    'list', 'lists', 'tag', 'tags',
    'photo', 'photos', 'image', 'images',
    
    # Common Words (legitimate context)
    'the', 'of', 'and', 'to', 'on', 'for', 'with',
    'all', 'name', 'names',
    
    # Specific Legitimate Sites
    'imdb', '123people', 'absoluteastronomy',
    'rootsweb', 'manta', 'wn',
    
    # Educational
    'school', 'schools', 'english',
    
    # Entertainment
    'show', 'shows', 'title', 'titles',
    'bio', 'bios',
    
    # Forums & Community
    'forum', 'forums', 'group', 'groups',
    
    # Other legitimate patterns
    'dp', 'pid', 'cs', 'st', 'cfm', 'shtml',
]


# ============================================================================
# DANH SÁCH TỪ KHÓA TRUNG TÍNH (Xuất hiện ở cả 2 loại tương đương)
# ============================================================================
NEUTRAL_KEYWORDS: List[str] = [
    'id', 'info', 'pub', 'cgi', 'home', 'pages',
    'page', 'view', 'new', 'go', 'biz', 'blog',
]


# ============================================================================
# HÀM TRÍCH XUẤT ĐẶC TRƯNG TỪ URL
# ============================================================================

def extract_words_from_url(url: str) -> List[str]:
    """
    Trích xuất các từ từ URL
    
    Args:
        url: URL cần phân tích
        
    Returns:
        List các từ đã được normalize (lowercase)
    """
    if not url or not isinstance(url, str):
        return []
    
    url_str = str(url).strip()
    if not url_str:
        return []
    
    # Loại bỏ scheme
    if '://' in url_str:
        url_str = url_str.split('://', 1)[1]
    
    # Loại bỏ www. ở đầu
    if url_str.startswith('www.'):
        url_str = url_str[4:]
    
    # Tách theo các ký tự phân cách
    SPLIT_CHARS = r'[/\?&=:#\-_\.]'
    parts = re.split(SPLIT_CHARS, url_str)
    
    words = []
    MIN_WORD_LENGTH = 2
    STOP_WORDS = {
        'www', 'http', 'https', 'com', 'org', 'net', 'edu', 'gov',
        'html', 'htm', 'php', 'asp', 'aspx', 'jsp', 'js', 'css',
    }
    
    for part in parts:
        part = part.strip().lower()
        
        if not part or len(part) < MIN_WORD_LENGTH:
            continue
        
        if part.isdigit() or part in STOP_WORDS:
            continue
        
        if not any(c.isalnum() for c in part):
            continue
        
        # Tách camelCase
        sub_words = re.split(r'(?=[A-Z])|_', part)
        sub_words = [sw.strip().lower() for sw in sub_words if sw.strip()]
        
        if len(sub_words) > 1:
            for sub_word in sub_words:
                if len(sub_word) >= MIN_WORD_LENGTH and sub_word not in STOP_WORDS:
                    words.append(sub_word)
        else:
            if len(part) >= MIN_WORD_LENGTH and part not in STOP_WORDS:
                words.append(part)
    
    return words


def extract_keyword_features(url: str) -> Dict[str, int]:
    """
    Trích xuất đặc trưng từ khóa từ URL
    
    Args:
        url: URL cần phân tích
        
    Returns:
        Dictionary chứa các đặc trưng:
        - has_phishing_keyword: 1 nếu có từ khóa phishing, 0 nếu không
        - has_legitimate_keyword: 1 nếu có từ khóa legitimate, 0 nếu không
        - phishing_keyword_count: Số lượng từ khóa phishing xuất hiện
        - legitimate_keyword_count: Số lượng từ khóa legitimate xuất hiện
        - neutral_keyword_count: Số lượng từ khóa trung tính xuất hiện
        - total_keyword_count: Tổng số từ khóa phát hiện được
        - phishing_keyword_ratio: Tỉ lệ từ khóa phishing / tổng từ khóa
        - legitimate_keyword_ratio: Tỉ lệ từ khóa legitimate / tổng từ khóa
    """
    words = extract_words_from_url(url)
    url_lower = url.lower() if url else ''
    
    # Đếm từ khóa
    phishing_count = 0
    legitimate_count = 0
    neutral_count = 0
    
    # Kiểm tra trong danh sách từ đã trích xuất
    for word in words:
        if word in PHISHING_KEYWORDS:
            phishing_count += 1
        elif word in LEGITIMATE_KEYWORDS:
            legitimate_count += 1
        elif word in NEUTRAL_KEYWORDS:
            neutral_count += 1
    
    # Kiểm tra trực tiếp trong URL (để bắt các từ có thể bị tách nhỏ)
    for keyword in PHISHING_KEYWORDS:
        if keyword in url_lower:
            phishing_count += 1
    
    for keyword in LEGITIMATE_KEYWORDS:
        if keyword in url_lower:
            legitimate_count += 1
    
    total_keywords = phishing_count + legitimate_count + neutral_count
    
    # Tính tỉ lệ
    phishing_ratio = phishing_count / total_keywords if total_keywords > 0 else 0.0
    legitimate_ratio = legitimate_count / total_keywords if total_keywords > 0 else 0.0
    
    return {
        'has_phishing_keyword': 1 if phishing_count > 0 else 0,
        'has_legitimate_keyword': 1 if legitimate_count > 0 else 0,
        'phishing_keyword_count': phishing_count,
        'legitimate_keyword_count': legitimate_count,
        'neutral_keyword_count': neutral_count,
        'total_keyword_count': total_keywords,
        'phishing_keyword_ratio': phishing_ratio,
        'legitimate_keyword_ratio': legitimate_ratio,
    }


def get_keyword_score(url: str) -> float:
    """
    Tính điểm từ khóa để đánh giá khả năng phishing
    
    Args:
        url: URL cần phân tích
        
    Returns:
        Điểm từ 0-1:
        - > 0.7: Có khả năng cao là phishing
        - 0.3-0.7: Không chắc chắn
        - < 0.3: Có khả năng cao là legitimate
    """
    features = extract_keyword_features(url)
    
    if features['total_keyword_count'] == 0:
        return 0.5  # Trung tính nếu không có từ khóa
    
    # Điểm dựa trên tỉ lệ từ khóa
    score = features['phishing_keyword_ratio']
    
    # Nếu có từ khóa phishing nhưng không có từ khóa legitimate, tăng điểm
    if features['phishing_keyword_count'] > 0 and features['legitimate_keyword_count'] == 0:
        score = min(1.0, score + 0.2)
    
    # Nếu có từ khóa legitimate nhưng không có từ khóa phishing, giảm điểm
    if features['legitimate_keyword_count'] > 0 and features['phishing_keyword_count'] == 0:
        score = max(0.0, score - 0.2)
    
    return score


# ============================================================================
# HÀM TIỆN ÍCH
# ============================================================================

def print_keyword_stats():
    """In thống kê về số lượng từ khóa"""
    print(f"Tổng số từ khóa PHISHING: {len(PHISHING_KEYWORDS)}")
    print(f"Tổng số từ khóa LEGITIMATE: {len(LEGITIMATE_KEYWORDS)}")
    print(f"Tổng số từ khóa NEUTRAL: {len(NEUTRAL_KEYWORDS)}")
    print(f"\nTổng cộng: {len(PHISHING_KEYWORDS) + len(LEGITIMATE_KEYWORDS) + len(NEUTRAL_KEYWORDS)} từ khóa")


if __name__ == "__main__":
    # Test
    print("=" * 80)
    print("URL KEYWORD FEATURES")
    print("=" * 80)
    print_keyword_stats()
    
    print("\n" + "=" * 80)
    print("TEST CÁC URL MẪU")
    print("=" * 80)
    
    test_urls = [
        "https://www.paypal.com/webscr/login",
        "https://www.facebook.com/people/John-Doe",
        "https://secure-account-verify.com/login",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://www.youtube.com/watch?v=123",
    ]
    
    for url in test_urls:
        print(f"\nURL: {url}")
        features = extract_keyword_features(url)
        score = get_keyword_score(url)
        print(f"  Features: {features}")
        print(f"  Score: {score:.3f} ({'PHISHING' if score > 0.7 else 'LEGITIMATE' if score < 0.3 else 'NEUTRAL'})")

