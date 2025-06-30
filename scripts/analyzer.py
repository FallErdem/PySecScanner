# analyzer.py
# Bu script, crawler tarafından bulunan linkleri okur,
# statik ve dinamik linkleri ayırır, dinamik linklerdeki parametreleri çıkarır
# ve URL'lerde statik güvenlik açığı kalıpları arar.

import os
import urllib.parse # URL'leri parçalamak ve parametreleri almak için
import logging

# Logging yapılandırması
logger = logging.getLogger(__name__)
if not logger.hasHandlers():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

# static_analysis.py'nin projenizin yapısına göre doğru import edilebildiğinden emin olun.
# Eğer Flask projenizde 'analysis' adında bir paketiniz varsa ve static_analysis.py onun içindeyse bu çalışır.
# Alternatif olarak, static_analysis_module ana fonksiyona parametre olarak da geçirilebilir.
try:
    from .analysis.static_analysis import analiz_et as static_analyze_url
except ImportError:
    logger.error("Hata: 'analysis' klasörü içinde 'static_analysis.py' veya içindeki 'analiz_et' fonksiyonu bulunamadı.")
    # Bu durumda scriptin devam etmemesi için bir istisna fırlatılabilir veya import edilen fonksiyon None olarak işaretlenebilir.
    # Web uygulamasında bu tür bir hata, görevin başarısız olmasına neden olmalı.
    # Şimdilik, eğer import edilemezse static_analyze_url None olacak ve aşağıda kontrol edilecek.
    static_analyze_url = None


# Ayarlar (Artık fonksiyon parametreleri olarak alınacak)
# INPUT_FILE = "bulunan_linkler.txt" # Crawler'ın çıktığı dosya
# OUTPUT_FILE = "analyzed_links.txt" # Analiz sonuçlarının yazılacağı dosya

# Statik dosya uzantıları listesi (Bu listeyi genişletebilirsiniz)
STATIC_EXTENSIONS = [
    '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg',
    '.webp', '.bmp', '.ico', '.woff', '.woff2', '.ttf', '.eot',
    '.otf', '.mp4', '.webm', '.ogg', '.mp3', '.wav', '.zip',
    '.rar', '.7z', '.tar', '.gz', '.bz2', '.pdf', '.doc', '.docx',
    '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv', '.xml', '.json',
]

# Bir URL'nin statik bir dosyaya işaret edip etmediğini kontrol eden fonksiyon
def is_static(url):
    try:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        for ext in STATIC_EXTENSIONS:
            if path.endswith(ext):
                return True
        # Query string varsa ve uzantısı yoksa genellikle dinamiktir.
        # Ancak /api/users/123 gibi uzantısız dinamik yollar da var.
        # Bu basit kontrol şimdilik yeterli olabilir.
    except Exception as e:
        logger.warning(f"URL parse edilirken hata (is_static): {url} - {e}")
        return False # Hata durumunda statik değilmiş gibi davran
    return False

# Bir URL'deki sorgu parametrelerini (GET parametreleri) çıkaran fonksiyon
def extract_parameters(url):
    try:
        parsed = urllib.parse.urlparse(url)
        query = parsed.query
        parameters = urllib.parse.parse_qs(query, keep_blank_values=True, strict_parsing=False)
        return parameters
    except Exception as e:
        logger.warning(f"URL parse edilirken hata (extract_parameters): {url} - {e}")
        return {} # Hata durumunda boş dictionary dön

# Analiz sonuçlarını bir dosyaya düzenli formatta yazan yardımcı fonksiyon
def write_analysis_result_to_file(file_handle, url, is_static_flag, parameters, static_threat_analysis_result):
    try:
        file_handle.write(f"URL: {url}\n")
        file_handle.write(f"Statik mi?: {'Evet' if is_static_flag else 'Hayır'}\n")

        if not is_static_flag:
            file_handle.write("Potansiyel Giriş Noktaları (GET Parametreleri):\n")
            if parameters:
                for param, values in parameters.items():
                    file_handle.write(f"  - {param}: {', '.join(values)}\n")
            else:
                file_handle.write("  (Bu dinamik URL'de GET parametresi bulunamadı.)\n")

            # static_analysis scriptinizin sonuçlarını ekle
            if static_threat_analysis_result: # Eğer analiz sonucu varsa (static_analyze_url None değilse)
                file_handle.write("URL Statik Güvenlik Analizi Sonucu:\n")
                file_handle.write(f"  Tehdit Var mı?: {'Evet' if static_threat_analysis_result.get('tehdit_var_mi') else 'Hayır'}\n")
                file_handle.write(f"  Bulunan Tehdit Sayısı: {static_threat_analysis_result.get('bulunan_tehdit_sayisi', 0)}\n")

                if static_threat_analysis_result.get('tehdit_var_mi'):
                    file_handle.write("  Bulunan Tehdit Detayları:\n")
                    for tehdit in static_threat_analysis_result.get('bulunan_tehditler', []):
                        file_handle.write(f"    - Tür: {tehdit.get('tur', 'Bilinmiyor')}\n")
                        file_handle.write(f"      Açıklama: {tehdit.get('aciklama', '')}\n")
                        file_handle.write(f"      Örnek Saldırı Payload'ı: {tehdit.get('ornek', '')}\n")
                else:
                    file_handle.write("  (URL'nin kendisinde bilinen statik tehdit kalıbı bulunamadı.)\n")
            else:
                file_handle.write("  (URL Statik Güvenlik Analizi yapılamadı - modül yüklenememiş olabilir.)\n")
        
        file_handle.write("-" * 30 + "\n")
    except IOError as e:
        logger.error(f"Analiz sonucu dosyaya yazılırken hata: {e}")
    except Exception as e:
        logger.exception(f"Analiz sonucu yazılırken beklenmedik hata: {e}")


# Ana analiz fonksiyonu (web uygulamasından çağrılacak)
def run_link_analysis(input_file_path: str, output_file_path: str, verbose: bool = False):
    """
    Verilen girdi dosyasındaki linkleri okur, analiz eder ve sonuçları çıktı dosyasına yazar.
    
    Args:
        input_file_path (str): Crawler tarafından oluşturulmuş linkleri içeren dosyanın yolu.
        output_file_path (str): Analiz sonuçlarının yazılacağı dosyanın yolu.
        verbose (bool): Ayrıntılı loglama için.
        
    Returns:
        bool: İşlem başarılıysa True, değilse False.
    """
    if verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose mod aktif edildi (analyzer).")
    else:
        logger.setLevel(logging.INFO)

    if static_analyze_url is None:
        logger.error("Statik analiz modülü (static_analysis.py) yüklenemediği için analiz işlemi devam ettirilemiyor.")
        return False

    if not os.path.exists(input_file_path):
        logger.error(f"Hata: Girdi dosyası '{input_file_path}' bulunamadı.")
        return False

    urls_to_analyze = []
    try:
        with open(input_file_path, "r", encoding="utf-8") as infile:
            urls_to_analyze = [line.strip() for line in infile if line.strip()]
    except IOError as e:
        logger.error(f"Girdi dosyası '{input_file_path}' okunurken hata: {e}")
        return False
    except Exception as e:
        logger.exception(f"Girdi dosyası okunurken beklenmedik hata: {e}")
        return False


    if not urls_to_analyze:
        logger.warning(f"Girdi dosyası '{input_file_path}' boş veya geçerli URL içermiyor.")
        # Boş dosya için yine de çıktı dosyası oluşturup başlık yazılabilir veya True dönülebilir.
        # Şimdilik True dönelim, çünkü hata değil.
        try:
            with open(output_file_path, "w", encoding="utf-8") as outfile: # Dosyayı oluştur/üzerine yaz
                outfile.write(f"# Analiz Raporu: {output_file_path}\n")
                outfile.write(f"# Kaynak Dosya: {input_file_path}\n")
                outfile.write(f"# Analiz Edilecek URL Bulunamadı.\n")
            return True
        except IOError as e:
            logger.error(f"Boş analiz raporu oluşturulurken hata '{output_file_path}': {e}")
            return False


    logger.info(f"'{input_file_path}' dosyasındaki {len(urls_to_analyze)} link okunuyor ve analiz ediliyor...")
    
    analyzed_count = 0
    try:
        with open(output_file_path, "w", encoding="utf-8") as outfile: # Dosyayı oluştur/üzerine yaz
            outfile.write(f"# Analiz Raporu: {output_file_path}\n")
            outfile.write(f"# Kaynak Dosya: {input_file_path}\n")
            outfile.write(f"# Toplam URL: {len(urls_to_analyze)}\n\n")

            for i, url in enumerate(urls_to_analyze):
                logger.info(f"Analiz ediliyor ({i+1}/{len(urls_to_analyze)}): {url}")

                is_static_flag = is_static(url)
                parameters = {}
                static_threat_analysis = {} # Başlangıçta boş

                if not is_static_flag:
                    parameters = extract_parameters(url)
                    if static_analyze_url: # Fonksiyon import edilebildiyse
                        static_threat_analysis = static_analyze_url(url)
                
                write_analysis_result_to_file(outfile, url, is_static_flag, parameters, static_threat_analysis)
                analyzed_count +=1
        
        logger.info(f"Analiz tamamlandı. {analyzed_count} URL analiz edildi. Sonuçlar '{output_file_path}' dosyasına kaydedildi.")
        return True

    except IOError as e:
        logger.error(f"Çıktı dosyası '{output_file_path}' yazılırken hata: {e}")
        return False
    except Exception as e:
        logger.exception(f"Analiz sırasında beklenmedik bir hata oluştu: {e}")
        return False

# Web uygulamasından çağrılırken bu __main__ bloğu çalışmayacaktır.
# Script artık bir modül olarak import edilecek ve run_link_analysis fonksiyonu çağrılacaktır.
# Örnek Çağrı (Flask uygulamasından veya başka bir scriptten):
# from analysis import analyzer # Eğer 'analysis' adında bir paketin içindeyse
#
# input_path = "/path/to/scan_results/unique_scan_id/bulunan_linkler.txt"
# output_path = "/path/to/scan_results/unique_scan_id/analyzed_links.txt"
# enable_verbose_logging = True
#
# success = analyzer.run_link_analysis(
# input_file_path=input_path,
# output_file_path=output_path,
# verbose=enable_verbose_logging
# )
# if success:
# print("Link analizi başarıyla tamamlandı.")
# else:
# print("Link analizi sırasında bir hata oluştu.")