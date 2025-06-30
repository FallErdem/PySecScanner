# scanner.py - Aktif Güvenlik Açığı Tarama Modülü

import requests
import urllib.parse
import os
import re
import time
import logging
from typing import List, Dict, Any, Optional # Gerekli tipler eklendi

# Logging yapılandırması
logger = logging.getLogger(__name__)
if not logger.hasHandlers():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

# Ayarlar (Fonksiyon parametresi olarak alınabilir veya sabit kalabilir)
DEFAULT_REQUEST_TIMEOUT = 10
DEFAULT_REQUEST_DELAY = 0.5

# --- Güvenlik Açığı Payloadları ---
SQLI_PAYLOADS = [
    "'", '"', "')", "'))",
    " OR 1=1-- ", " OR '1'='1'-- ",
    " AND 1=1-- ", " AND '1'='1'-- ",
    " OR 1=2-- ", " OR '1'='2'-- ",
    " AND 1=2-- ", " AND '1'='2'-- ",
    " ORDER BY 99-- ",
    "' UNION SELECT 1,2,3 -- ",
]
SQLI_ERROR_PATTERNS = [
    r"SQL syntax", r"mysql_fetch_array\(\)", r"ORA-\d{5}", r"Unclosed quotation mark",
    r"Microsoft JET Database Engine", r"Error converting data type",
    r"valid MySQL result resource", r"PostgreSQL error", r"Warning: mysql_",
    r"quoted string not properly terminated", r"driver for sql server", r"Oracle error",
    r"cn\.Execute", r"Microsoft Access Driver", r"SQLSTATE", r"syntax error",
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<svg/onload=alert(1)>", "<img src=x onerror=alert(1)>",
    "<a href='javascript:alert(1)'>XSS</a>", "<iframe src='javascript:alert(1)'></iframe>",
    "><script>alert(1)</script>", "'><script>alert(1)</script>", "\"><script>alert(1)</script>",
    "<ScRipT>alert(1)</sCriPt>"
]
XSS_REFLECTION_INDICATORS = [
    "alert(1)", "<script>alert(1)</script>", "<svg/onload=",
    "onerror=alert(1)", "javascript:alert(1)"
]

# --- Yardımcı Fonksiyonlar ---
def inject_payload_to_url(base_url: str, param_name_to_inject: str, payload_to_inject: str) -> str:
    """
    Verilen URL'deki belirli bir GET parametresinin değerini verilen payload ile değiştirir.
    Eğer parametre yoksa, yeni bir parametre olarak ekler (bu durum analizden gelen veriyle pek oluşmaz).
    """
    try:
        parsed_url = urllib.parse.urlparse(base_url)
        query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
        
        # Değiştirilecek veya eklenecek parametre için payload'ı ayarla
        # parse_qs değerleri liste olarak döndürdüğü için payload'ı da liste içine alıyoruz.
        query_params[param_name_to_inject] = [payload_to_inject]
        
        new_query_string = urllib.parse.urlencode(query_params, doseq=True)
        
        new_url = urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query_string,
            parsed_url.fragment # Fragment'ı koruyabiliriz veya atabiliriz, şimdilik koruyalım
        ))
        return new_url
    except Exception as e:
        logger.warning(f"Payload enjeksiyonu sırasında URL oluşturma hatası ({base_url}, {param_name_to_inject}): {e}")
        return base_url # Hata durumunda orijinal URL'yi dön

def parse_analyzed_file(file_path: str) -> Optional[List[Dict[str, Any]]]:
    analyzed_data = []
    current_entry = None
    
    if not os.path.exists(file_path):
        logger.error(f"Analiz dosyası bulunamadı: {file_path}")
        return None

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): # Yorum satırlarını veya boş satırları atla
                    continue

                if line.startswith("URL: "):
                    if current_entry:
                        analyzed_data.append(current_entry)
                    current_entry = {"url": line.replace("URL: ", "", 1), "is_static": False, "parameters": {}}
                elif current_entry:
                    if line.startswith("Statik mi?: "):
                        current_entry["is_static"] = (line.replace("Statik mi?: ", "", 1) == "Evet")
                    elif line.startswith("- "): # Parametre satırı
                        try:
                            param_part = line.replace("- ", "", 1).split(':', 1)
                            if len(param_part) == 2:
                                param_name = param_part[0].strip()
                                param_values_str = param_part[1].strip()
                                current_entry["parameters"][param_name] = [v.strip() for v in param_values_str.split(',') if v.strip()]
                        except Exception as e:
                            logger.warning(f"Parametre satırı ayrıştırılamadı: '{line}' - Hata: {e}")
                    # Statik tehdit analizi sonuçlarını parse etme kısmı bu scanner için gerekli değil,
                    # çünkü scanner aktif testlere odaklanıyor. Analyzer zaten bu bilgiyi dosyaya yazdı.
                    # Eğer scanner da bu bilgiyi kullanacaksa, parse mantığı eklenebilir.
        if current_entry:
            analyzed_data.append(current_entry)
        return analyzed_data
    except IOError as e:
        logger.error(f"Analiz dosyası okunurken hata '{file_path}': {e}")
        return None
    except Exception as e:
        logger.exception(f"Analiz dosyası parse edilirken beklenmedik hata '{file_path}': {e}")
        return None

# --- Güvenlik Açığı Kontrol Fonksiyonları ---
def check_sqli(url: str, param_name: str, original_param_value: str, session: requests.Session, timeout: int, delay: float) -> List[Dict[str, Any]]:
    vulnerabilities = []
    logger.debug(f"SQLi kontrol ediliyor: {url} - Parametre: {param_name}")

    for payload in SQLI_PAYLOADS:
        test_url = inject_payload_to_url(url, param_name, payload)
        logger.debug(f"SQLi testi: {test_url}")
        try:
            response = session.get(test_url, timeout=timeout)
            if response.text:
                response_text_lower = response.text.lower()
                for error_pattern in SQLI_ERROR_PATTERNS:
                    match = re.search(error_pattern, response_text_lower)
                    if match:
                        vuln_details = {
                            "type": "SQL Injection (Error Based)", "url": url, "method": "GET",
                            "parameter": param_name, "payload": payload,
                            "details": f"Yanıt metni '{match.group(0)}' hata kalıbını içeriyor."
                        }
                        vulnerabilities.append(vuln_details)
                        logger.warning(f"POTANSİYEL SQL Injection: {url} Param: {param_name} Payload: {payload}")
                        break # Bu payload için hata bulundu, sonraki payload'a geç
        except requests.exceptions.RequestException as e:
            logger.debug(f"SQLi testi sırasında istek hatası: {test_url} - {e}")
        except Exception as e:
            logger.exception(f"SQLi testi sırasında beklenmedik hata: {test_url} - {e}")
        time.sleep(delay)
    return vulnerabilities

def check_xss(url: str, param_name: str, original_param_value: str, session: requests.Session, timeout: int, delay: float) -> List[Dict[str, Any]]:
    vulnerabilities = []
    logger.debug(f"XSS kontrol ediliyor: {url} - Parametre: {param_name}")

    for payload in XSS_PAYLOADS:
        encoded_payload = urllib.parse.quote_plus(payload)
        test_url = inject_payload_to_url(url, param_name, encoded_payload)
        logger.debug(f"XSS testi: {test_url}")
        try:
            response = session.get(test_url, timeout=timeout)
            # response.raise_for_status() # XSS'de 200 OK yanıtı içinde yansıma olabilir.
            if response.text:
                response_text_lower = response.text.lower() # Karşılaştırma için küçük harf
                # Payload'ın kendisi yansıyor mu (decode edilmiş haliyle karşılaştır)
                # veya belirteçler yansıyor mu kontrol et.
                # Enjekte edilen payload'ın decode edilmiş halini de aramak iyi bir fikir.
                decoded_payload_lower = urllib.parse.unquote_plus(payload).lower()

                if payload.lower() in response_text_lower or decoded_payload_lower in response_text_lower :
                    vuln_details = {
                        "type": "Reflected XSS", "url": url, "method": "GET",
                        "parameter": param_name, "payload": payload,
                        "details": f"Payload '{payload}' yanıt metninde yansıdı."
                    }
                    vulnerabilities.append(vuln_details)
                    logger.warning(f"POTANSİYEL Reflected XSS: {url} Param: {param_name} Payload: {payload}")
                    continue # Bu payload ile yansıma bulundu, sonraki payload'a geç.
                
                # Eğer tam payload yansımı yoksa, belirteçleri kontrol et
                for indicator in XSS_REFLECTION_INDICATORS:
                    if indicator.lower() in response_text_lower:
                        vuln_details = {
                            "type": "Reflected XSS", "url": url, "method": "GET",
                            "parameter": param_name, "payload": payload,
                            "details": f"Payload'ın '{indicator}' kısmı yanıt metninde yansıdı."
                        }
                        vulnerabilities.append(vuln_details)
                        logger.warning(f"POTANSİYEL Reflected XSS (indicator): {url} Param: {param_name} Payload: {payload}")
                        break # Bu payload için belirteç bulundu, sonraki payload'a geç
                else: # İçteki for döngüsü break olmadan biterse (belirteç bulunamadı)
                    continue # Sonraki payload'a geç
                break # Belirteç bulunduysa dıştaki for döngüsünden de çık (bu payload için test bitti)

        except requests.exceptions.RequestException as e:
            logger.debug(f"XSS testi sırasında istek hatası: {test_url} - {e}")
        except Exception as e:
            logger.exception(f"XSS testi sırasında beklenmedik hata: {test_url} - {e}")
        time.sleep(delay)
    return vulnerabilities

# Ana tarama fonksiyonu (web uygulamasından çağrılacak)
def run_vulnerability_scan(analyzed_file_path: str, 
                           report_file_path: str, 
                           verbose: bool = False,
                           request_timeout: int = DEFAULT_REQUEST_TIMEOUT,
                           request_delay: float = DEFAULT_REQUEST_DELAY) -> bool:
    """
    Verilen analiz dosyasındaki URL'leri okur, aktif güvenlik taraması yapar ve sonuçları rapor dosyasına yazar.
    """
    if verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose mod aktif edildi (scanner).")
    else:
        logger.setLevel(logging.INFO)

    logger.info(f"'{analyzed_file_path}' dosyasındaki analiz sonuçları okunuyor...")
    analyzed_links_data = parse_analyzed_file(analyzed_file_path)

    if analyzed_links_data is None:
        logger.error("Analiz verisi okunamadığı için tarama başlatılamıyor.")
        return False
    
    if not analyzed_links_data:
        logger.warning(f"Analiz edilecek link bulunamadı: {analyzed_file_path}")
        try:
            with open(report_file_path, "w", encoding="utf-8") as report_f:
                report_f.write("### Güvenlik Açığı Tarama Raporu ###\n\n")
                report_f.write(f"Tarama Başlangıcı: {time.ctime()}\n")
                report_f.write(f"Kaynak Analiz Dosyası: {analyzed_file_path}\n")
                report_f.write("Analiz edilecek URL bulunamadı.\n")
                report_f.write("-" * 40 + "\n\n")
                report_f.write(f"Rapor Sonu: {time.ctime()}\n")
            return True # Hata değil, işlem tamamlandı
        except IOError as e:
            logger.error(f"Boş rapor dosyası '{report_file_path}' yazılırken hata: {e}")
            return False


    logger.info(f"{len(analyzed_links_data)} link analizi bulundu. Tarama başlıyor...")
    found_vulnerabilities_overall: List[Dict[str, Any]] = []
    tested_dynamic_links_count = 0

    session = requests.Session()
    # session.headers.update({'User-Agent': 'MyWebAppScanner/1.0'}) # İsteğe bağlı User-Agent

    try:
        with open(report_file_path, "w", encoding="utf-8") as report_f:
            report_f.write("### Güvenlik Açığı Tarama Raporu ###\n\n")
            report_f.write(f"Tarama Başlangıcı: {time.ctime()}\n")
            report_f.write(f"Kaynak Analiz Dosyası: {analyzed_file_path}\n")
            report_f.write("-" * 40 + "\n\n")

            for i, entry in enumerate(analyzed_links_data):
                url = entry["url"]
                is_static_flag = entry.get("is_static", True) # is_static yoksa True varsayalım
                parameters = entry.get("parameters", {})

                logger.info(f"İşleniyor ({i+1}/{len(analyzed_links_data)}): {url}")
                report_f.write(f"URL: {url}\n")

                if is_static_flag or not parameters:
                    status_note = "Statik Link" if is_static_flag else "Dinamik Link (GET Parametresi Yok)"
                    logger.debug(f"{status_note}, aktif tarama atlanıyor: {url}")
                    report_f.write(f"Durum: {status_note} (Aktif Tarama Atlandı)\n")
                else:
                    tested_dynamic_links_count +=1
                    logger.debug(f"Dinamik URL, parametreler test ediliyor: {url}")
                    report_f.write(f"Durum: Dinamik Link (GET Parametreleri Var)\n")
                    report_f.write(f"Test Edilen Parametreler ({len(parameters)} adet): {', '.join(parameters.keys())}\n")
                    
                    url_vulnerabilities: List[Dict[str, Any]] = []
                    for param_name, param_values in parameters.items():
                        original_value = param_values[0] if param_values else ""
                        
                        sqli_vulns = check_sqli(url, param_name, original_value, session, request_timeout, request_delay)
                        url_vulnerabilities.extend(sqli_vulns)
                        
                        xss_vulns = check_xss(url, param_name, original_value, session, request_timeout, request_delay)
                        url_vulnerabilities.extend(xss_vulns)
                    
                    if url_vulnerabilities:
                        report_f.write("Bulunan Potansiyel Zafiyetler:\n")
                        for vuln in url_vulnerabilities:
                            report_f.write(f"  - Tür: {vuln['type']}\n")
                            report_f.write(f"    Parametre: {vuln['parameter']}\n")
                            report_f.write(f"    Payload: {vuln['payload']}\n")
                            report_f.write(f"    Detaylar: {vuln['details']}\n")
                        found_vulnerabilities_overall.extend(url_vulnerabilities)
                    else:
                        report_f.write("  (Bu URL'de test edilen parametrelerde bilinen bir zafiyet bulunamadı.)\n")
                
                report_f.write("-" * 30 + "\n\n")

            # Tarama Özeti (with bloğu içinde)
            report_f.write("\n### Tarama Özeti ###\n\n")
            report_f.write(f"Toplam Analiz Edilen Link Sayısı (kaynaktan): {len(analyzed_links_data)}\n")
            report_f.write(f"Aktif Taramaya Dahil Edilen Dinamik Link Sayısı: {tested_dynamic_links_count}\n")
            report_f.write(f"Toplam Bulunan Potansiyel Zafiyet Sayısı: {len(found_vulnerabilities_overall)}\n")
            
            vuln_counts: Dict[str, int] = {}
            for vuln in found_vulnerabilities_overall:
                vuln_type = vuln['type']
                vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
            if vuln_counts:
                report_f.write("Zafiyet Türlerine Göre Dağılım:\n")
                for v_type, count in vuln_counts.items():
                    report_f.write(f"  - {v_type}: {count}\n")
            
            report_f.write(f"\nRapor Sonu: {time.ctime()}\n")
        
        logger.info(f"Tarama tamamlandı.")
        logger.info(f"Toplam {len(analyzed_links_data)} link analizi içinde, {tested_dynamic_links_count} dinamik link aktif olarak test edildi.")
        logger.info(f"Toplam {len(found_vulnerabilities_overall)} potansiyel zafiyet bulundu.")
        logger.info(f"Detaylı rapor '{report_file_path}' dosyasına kaydedildi.")
        return True

    except IOError as e:
        logger.error(f"Rapor dosyası '{report_file_path}' yazılırken hata: {e}")
        return False
    except Exception as e:
        logger.exception(f"Tarama sırasında beklenmedik bir hata oluştu: {e}")
        return False

# Örnek Çağrı
# from analysis import scanner
#
# analyzed_path = "/path/to/scan_results/unique_scan_id/analyzed_links.txt"
# report_path = "/path/to/scan_results/unique_scan_id/vulnerability_report.txt"
#
# success = scanner.run_vulnerability_scan(
# analyzed_file_path=analyzed_path,
# report_file_path=report_path,
# verbose=True,
# request_timeout=15, # Örneğin timeout artırılabilir
# request_delay=1.0 # Örneğin delay artırılabilir
# )
# if success:
# print("Zafiyet taraması başarıyla tamamlandı.")
# else:
# print("Zafiyet taraması sırasında bir hata oluştu.")