# Gerekli kütüphaneleri içe aktarma
import requests # HTTP istekleri göndermek için kullanılır
import logging  # Log mesajları (bilgi, uyarı, hata) üretmek için kullanılır
# argparse ve sys artık doğrudan bu script içinde kullanılmayacak, web uygulamasından çağrılacak.
import time     # İstekler arasına bekleme eklemek için kullanılır
import os       # Dosya işlemleri için kullanılır (çıktı dosyasını silmek gibi)
from bs4 import BeautifulSoup # BeautifulSoup, web sitesi içeriğini (HTML) ayrıştırmak ve linkleri bulmak için kullanılır
from urllib.parse import urljoin, urlparse # URL'leri işlemek için kullanılır
from typing import List, Set, Tuple, Optional

# Yeniden deneme ayarları
MAX_RETRIES = 3      # Başarısız istekler için maksimum deneme sayısı
RETRY_DELAY = 2      # İlk yeniden deneme öncesi bekleme süresi (saniye)
RETRY_MULTIPLIER = 2 # Sonraki denemelerde bekleme süresini artırma kat sayısı (üs alınarak artar)

# Logging yapılandırması
# Web uygulamasında bu yapılandırma Flask'ın kendi log config'i ile çakışmaması için
# dikkatli yönetilmeli veya Flask'ın loglarına entegre edilmeli.
# Şimdilik, eğer bu script ayrı bir işlem olarak (örn. Celery worker) çalışacaksa bu kalabilir.
# Eğer doğrudan Flask app context'inde çalışacaksa, Flask'ın logger'ını kullanmak daha iyi olabilir.
# Bu örnekte temel yapılandırmayı koruyoruz.
logger = logging.getLogger(__name__) # Modül seviyesinde logger oluşturmak daha iyi bir pratiktir.
if not logger.hasHandlers(): # Birden fazla handler eklenmesini önlemek için kontrol
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', # Log mesajının formatı
                        datefmt='%Y-%m-%d %H:%M:%S') # Zaman damgası formatı

# Varsayılan User-Agent başlığı
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Ana tarama fonksiyonu
def crawl_site(base_url: str,
               max_depth: int = 2,
               timeout: int = 10,
               output_file_path: str = "bulunan_linkler.txt", # Dosya adı yerine tam yolu alacak şekilde ismi değiştirdim - (Daha iyi oldu bence)
               user_agent: str = DEFAULT_USER_AGENT,
               verify_ssl: bool = True,
               sleep_time: float = 1.0,
               verbose: bool = False) -> List[str]: # Verbose parametresi eklendi
    """
    Verilen URL'den başlayarak web sitesini tarar, dahili linkleri bulur,
    çıktı dosyasına kaydeder. İstek hatalarında yeniden deneme yapar.
    Eğer bir http:// isteği başarısız olursa https:// versiyonunu dener.
    robots.txt kurallarını yok ettim duruma göre açılabilir

    Args:
        base_url (str): Başlangıç URL'si.
        max_depth (int): Maksimum tarama derinliği.
        timeout (int): HTTP istekleri için zaman aşımı.
        output_file_path (str): Bulunan dahili linklerin yazılacağı tam dosya yolu.
        user_agent (str): User-Agent başlığı.
        verify_ssl (bool): HTTPS sertifika doğrulaması.
        sleep_time (float): Her istek arası genel bekleme süresi.
        verbose (bool): Ayrıntılı loglama (DEBUG seviyesi) için.

    Returns:
        List[str]: Bulunan dahili linklerin listesi (dosyaya yazılanlarla aynı).
    """
    if verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose mod aktif edildi (crawler).")
    else:
        logger.setLevel(logging.INFO)


    processed_or_queued: Set[str] = set()
    to_visit: List[Tuple[str, int]] = []
    found_links: List[str] = []

    # Başlangıç URL'sinin temel formatını kontrol et
    parsed_initial_url = urlparse(base_url)
    if not parsed_initial_url.scheme in ['http', 'https']:
        logger.error(f"Geçersiz URL formatı: '{base_url}'. URL 'http://' veya 'https://' ile başlamalıdır.")
        return [] # Hata durumunda boş liste dön, programı sonlandırma

    to_visit.append((base_url, 0))

    parsed_base = urlparse(base_url)
    base_domain = parsed_base.netloc

    if not base_domain:
        logger.error(f"crawl_site fonksiyonuna geçersiz veya eksik URL geldi: {base_url}")
        return []

    session = requests.Session()
    session.headers.update({'User-Agent': user_agent})

    # SSL doğrulama kapatıldıysa uyarı ver ve requests'in SSL uyarılarını kapat.
    if not verify_ssl:
        logger.warning("HTTPS sertifika doğrulaması devre dışı bırakıldı! Bu güvensizdir.")
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            logger.warning("urllib3 kütüphanesi bulunamadı, SSL uyarıları kapatılamadı.")


    # Eğer çıktı dosyası belirtilen isimde zaten varsa, üzerine yazmak için dosyayı siler.
    # Bu, her tarama için yeni bir dosya oluşturuluyorsa veya append modu kullanılacaksa değiştirilebilir.
    # Şimdilik, web uygulamasının her tarama için farklı bir output_file_path sağlaması beklenir.
    try:
        # Dosyayı yazma modunda açarak içeriğini temizle (veya oluştur)
        with open(output_file_path, "w", encoding="utf-8") as f:
            pass # Sadece dosyayı boşaltmak veya oluşturmak için
        logger.info(f"Çıktı dosyası '{output_file_path}' tarama için hazırlandı/temizlendi.")
    except IOError as e:
        logger.error(f"Çıktı dosyası '{output_file_path}' hazırlanamadı/temizlenemedi: {e}")
        return [] # Dosya işlemi hatasında boş liste dön


    logger.info(f"Tarama Başladı: {base_url} (Maks Derinlik: {max_depth}, Çıktı: {output_file_path})")
    logger.warning("robots.txt kontrolü bu script versiyonunda devre dışıdır.") # Bu uyarıyı koruyalım
    processed_or_queued.add(base_url)

    while to_visit:
        current_url, depth = to_visit.pop(0)
        retries = 0
        current_delay = RETRY_DELAY
        response = None
        http_failed_try_https = False

        while retries < MAX_RETRIES:
            logger.info(f"Taranıyor (Derinlik {depth}/{max_depth}, Deneme {retries + 1}/{MAX_RETRIES}): {current_url}")
            try:
                response = session.get(current_url, timeout=timeout, verify=verify_ssl)
                response.raise_for_status()
                break
            except requests.exceptions.RequestException as e:
                logger.warning(f"İstek hatası ({retries + 1}. deneme): {current_url} - {type(e).__name__}: {e}")
                status_code = None
                if hasattr(e, 'response') and e.response is not None:
                    status_code = e.response.status_code
                    if status_code == 404:
                        logger.error(f"HTTP Hatası: 404 Bulunamadı - {current_url}")
                        response = None
                        retries = MAX_RETRIES
                        break
                    elif status_code == 429:
                         logger.warning(f"HTTP Hatası: 429 Çok Fazla İstek ({retries + 1}. deneme): {current_url}")

                is_connection_error = isinstance(e, requests.exceptions.ConnectionError)
                is_http_error_retryable = (status_code is not None and status_code != 404 and status_code != 429)

                if current_url.startswith('http://') and (is_connection_error or is_http_error_retryable):
                    https_url = current_url.replace('http://', 'https://', 1)
                    logger.info(f"HTTP isteği başarısız oldu. HTTPS olarak tekrar denemek için sıraya ekleniyor: {https_url}")
                    # Aynı derinlikte ve listenin başına ekle
                    if https_url not in processed_or_queued: # HTTPS versiyonu daha önce eklenmediyse
                        to_visit.insert(0, (https_url, depth))
                        processed_or_queued.add(https_url) # Sıraya eklendiği için işlenmiş say
                    http_failed_try_https = True
                    retries = MAX_RETRIES
                    break
            except Exception as e:
                 logger.exception(f"Beklenmedik hata ({current_url}, {retries + 1}. deneme): {e}")
                 response = None
                 retries = MAX_RETRIES
                 break
            
            if http_failed_try_https: # Bu iç döngüden çıkmak için
                break

            if retries < MAX_RETRIES - 1:
                 logger.info(f"Sonraki deneme için {current_delay:.1f} saniye bekleniyor...")
                 time.sleep(current_delay)
                 current_delay *= RETRY_MULTIPLIER
            retries += 1

        if http_failed_try_https: # Bu dış döngünün bu iterasyonunu atlamak için
            continue

        if response is None or (hasattr(response, 'status_code') and response.status_code >= 400):
             if response is not None : # Sadece HTTP hatası ise
                  logger.error(f"Maksimum {MAX_RETRIES} deneme sonrası HTTP Hatası ({response.status_code}), atlanıyor: {current_url}")
             else: # response None ise (örn. ConnectionError sonrası)
                   logger.error(f"Maksimum {MAX_RETRIES} deneme sonrası istek hala başarısız (Yanıt Yok), atlanıyor: {current_url}")
             time.sleep(sleep_time) # Başarısız istek sonrası da bekleme
             continue

        try:
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type:
                 logger.debug(f"HTML olmayan içerik atlandı ({content_type}): {current_url}")
                 time.sleep(sleep_time) # HTML olmayanlar için de bekleme
                 continue

            soup = BeautifulSoup(response.text, "html.parser")
            newly_found_count = 0
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
                    continue

                full_url = urljoin(current_url, href)
                parsed_full = urlparse(full_url)

                if parsed_full.netloc == base_domain and parsed_full.scheme in ['http', 'https']:
                    clean_url = urlparse(full_url)._replace(fragment="").geturl()
                    if clean_url not in processed_or_queued:
                        processed_or_queued.add(clean_url)
                        if depth < max_depth:
                            to_visit.append((clean_url, depth + 1))
                        
                        # Dosyaya yazma işlemini de found_links'e ekleme ile aynı anda yapalım
                        # Bu, fonksiyonun sonunda tüm listeyi yazmaktan daha iyi olabilir,
                        # özellikle uzun süren taramalarda ara çıktıları kaydetmek için.
                        try:
                            with open(output_file_path, "a", encoding="utf-8") as f:
                                f.write(clean_url + "\n")
                            found_links.append(clean_url) # Sadece başarılı yazılırsa listeye ekle
                            newly_found_count += 1
                        except IOError as e:
                            logger.error(f"Dosyaya yazma hatası ('{output_file_path}'): {e}")
            
            if newly_found_count > 0:
                logger.debug(f"  -> {current_url} sayfasından {newly_found_count} yeni link bulundu ve '{output_file_path}' dosyasına eklendi.")

        except Exception as e:
            logger.exception(f"İçerik işleme sırasında beklenmedik hata ({current_url}): {e}")
        
        logger.debug(f"{sleep_time:.1f} saniye genel bekleme süresi uygulanıyor...")
        time.sleep(sleep_time)

    logger.info(f"Tarama Tamamlandı: {base_url}")
    logger.info(f"Toplam Bulunan Benzersiz Dahili Link Sayısı (işlenen/sıraya eklenen): {len(processed_or_queued)}")
    logger.info(f"Sonuçlar (bulunan ve filtrelenen linkler) '{output_file_path}' dosyasına kaydedildi.")
    # Fonksiyon artık sadece dosyaya yazılan linkleri (found_links) döndürüyor.
    # processed_or_queued tüm keşfedilenleri (başlangıç URL'si dahil) içerir.
    # Çıktı dosyasıyla tutarlı olması için found_links (sadece yeni bulunan ve dosyaya yazılanlar) daha uygun olabilir.
    return found_links

# Web uygulamasından çağrılırken aşağıdaki __main__ bloğu çalışmayacaktır.
# Bu script artık bir modül olarak import edilecek ve crawl_site fonksiyonu doğrudan çağrılacaktır.
# Örnek Çağrı (Flask uygulamasından veya başka bir scriptten):
# from analysis import crawler # Eğer 'analysis' adında bir paketin içindeyse
#
# target_url = "https://example.com"
# scan_depth = 1
# output_path = "/path/to/scan_results/unique_scan_id/found_links.txt"
# user_agent_string = "MyWebAppScanner/1.0"
# verify_certificates = True
# request_delay = 0.5
# enable_verbose_logging = True
#
# discovered_links = crawler.crawl_site(
# base_url=target_url,
# max_depth=scan_depth,
# output_file_path=output_path,
# user_agent=user_agent_string,
# verify_ssl=verify_certificates,
# sleep_time=request_delay,
# verbose=enable_verbose_logging
# )
# print(f"Crawler {len(discovered_links)} link buldu ve dosyaya yazdı.")