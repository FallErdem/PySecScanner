import re
import urllib.parse

# 1. Tehdit türlerine göre gelişmiş pattern listesi
SABIT_PATTERNLER = {
    "SQL Injection": [
        r"(?i)\bUNION\s+SELECT\b",
        r"(?i)OR\s+\d+=\d+", 
        r"(?i)DROP\s+TABLE", 
        r"(?i)INFORMATION_SCHEMA",
        r"(?i)\bSLEEP\(\d+\)",            
        r"(?i)BENCHMARK\((.*?),",         
        r"(?i)WAITFOR\s+DELAY",           
        r"(?i)xp_cmdshell",               
        r"(?i)exec\s+xp_",            
        r"(?i)('|\%27)\s*--",         # tek tırnak + yorum
        r"(?i)select(\s|%20|\+)*\*(\s|%20|\+)*from",
    ],
    "XSS": [
        r"(?i)<script.*?>",
        r"(?i)javascript:",
        r"(?i)on\w+=['\"].*?['\"]",        
        r"(?i)<iframe.*?>",
        r"(?i)<svg.*?onload=.*?>",
        r"(?i)<body.*?onload=.*?>",
        r"(?i)<img\s+[^>]*onerror\s*=\s*['\"]?[^>]+['\"]?",
        r"(?i)onerror\s*=\s*['\"]?alert\(.*?\)",
        r"(?i)onload\s*=\s*['\"]?alert\s*\(",
    ],
    "Command Injection": [
    # sadece cmd=, exec= gibi parametrelerdeki komutları yakalar
    r"(?i)(cmd=|exec=|run=).*?\b(cat|ls|ping|wget|curl|dir|netstat|ipconfig|rm|whoami)\b",
    
    # herhangi bir parametrede hem ayırıcı hem komut varsa (ör: ?ip=127.0.0.1;cat /etc/passwd)
    r"(?i)[\?\&][a-z0-9_]+=.*?(\;|\||\&\&).*?\b(cat|ls|ping|wget|curl|dir|netstat|ipconfig|rm|whoami)\b",
    
    # $(), backtick gibi shell injection yapıları
    r"(\$\(.+?\)|`.+?`)"
    ],
    "Directory Traversal": [
        r"(\.\./)+",
        r"(%2e%2e%2f|%2e%2e%5c)+",
        r"\.\.\\",  
        r"/etc/passwd",      # Bu command inj ile karışabiliyor ekstra koşullu bir tanım yapmak gerek veya silinecek. -- EKLENDİ
        r"(\.\.%2f)+",      # = ../
    ]
}

# 2. Tehdit türlerine açıklama ve örnek bilgisi
THREAT_INFO = {
    "SQL Injection": {
        "desc": "Veritabanına zararlı SQL sorguları enjekte ederek veri sızdırabilir veya silebilir.",
        "example": "' OR 1=1--"
    },
    "XSS": {
        "desc": "Kullanıcının tarayıcısında zararlı JavaScript kodu çalıştırılır.",
        "example": "<script>alert('x')</script>"
    },
    "Command Injection": {
        "desc": "Sunucuda komut çalıştırılarak sistem ele geçirilmeye çalışılır.",
        "example": "cmd=rm -rf /"
    },
    "Directory Traversal": {
        "desc": "Dosya sisteminde geri klasörlere çıkılarak gizli dosyalara erişilmeye çalışılır.",
        "example": "../etc/passwd"
    }
}


# 3. Ana analiz fonksiyonu
def analiz_et(url):
    url_kucuk = urllib.parse.unquote(url.lower())  # decode edilmiş URL üzerinden analiz et
    detayli_tehditler = []
    bulunan_patternler = []

    for tehdit_turu, pattern_listesi in SABIT_PATTERNLER.items():
        for pattern in pattern_listesi:
            if re.search(pattern, url_kucuk):

                #özel kontrol: sadece "Directory Traversal" için - command ile karışmaması için ekstra koşul
                if tehdit_turu == "Directory Traversal":
                    if ("../" not in url_kucuk and
                        "%2e%2e" not in url_kucuk and
                        "..\\" not in url_kucuk):
                        continue  # directory traversal gibi değilse atla

                bulunan_patternler.append(pattern)
                detayli_tehditler.append({
                    "tur": tehdit_turu,
                    "aciklama": THREAT_INFO[tehdit_turu]["desc"],
                    "ornek": THREAT_INFO[tehdit_turu]["example"]
                })
                break  # Aynı türden ilk eşleşme yeterli

    return {
        "url": url,
        "tehdit_var_mi": bool(detayli_tehditler),
        "bulunan_tehdit_sayisi": len(detayli_tehditler),
        "bulunan_tehditler": detayli_tehditler
    }
