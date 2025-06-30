import math
import json
import logging
import os # Dosya yolu işlemleri için eklendi (os.path.exists vb. için gerekli olabilir)
from collections import Counter
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List

# Logging yapılandırması
logger = logging.getLogger(__name__)
if not logger.hasHandlers():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

# Varsayılan dosya adları artık kullanılmayacak, yollar parametre olarak gelecek.
# DEFAULT_INPUT_FILENAME = "bulunan_linkler.txt"
# DEFAULT_OUTPUT_FILENAME = "url_entropi_analizi.json"

def calculate_shannon_entropy(text: str) -> float: # text parametresi str olmalı, float değil
    """
    Verilen bir metin dizesinin Shannon entropisini hesaplar.
    """
    if not text or len(text) < 2: # En az 2 karakter olmalı ki olasılık hesabı anlamlı olsun
        return 0.0
    
    try:
        counts = Counter(text)
        text_length = float(len(text))
        entropy = 0.0
        for count in counts.values():
            if count > 0: # count 0 ise log tanımsız olur, gereksiz ama sağlamlık için.
                probability = count / text_length
                entropy -= probability * math.log2(probability)
        return entropy
    except Exception as e:
        logger.warning(f"Entropi hesaplanırken hata: '{text[:50]}...' - {e}")
        return 0.0 # Hata durumunda 0 entropi dön

def analyze_url_entropy(url: str) -> Dict[str, Any]:
    """
    Verilen bir URL'nin çeşitli kısımlarının entropisini analiz eder.
    """
    try:
        parsed_url = urlparse(url)
        path = parsed_url.path
        query = parsed_url.query

        entropy_results = {
            "url": url,
            "path_entropy": calculate_shannon_entropy(path) if path else 0.0,
            "path_segments_entropy": [],
            "query_string_entropy": calculate_shannon_entropy(query) if query else 0.0,
            "query_params_entropy": {}
        }

        if path:
            segments = path.strip('/').split('/')
            for segment in segments:
                if segment: # Boş segmentleri atla
                    entropy_results["path_segments_entropy"].append({
                        "segment": segment,
                        "entropy": calculate_shannon_entropy(segment)
                    })
        if query:
            params = parse_qs(query, keep_blank_values=True)
            for param_name, param_values in params.items():
                entropy_results["query_params_entropy"][param_name] = [
                    {"value": val, "entropy": calculate_shannon_entropy(val)} for val in param_values if val # Boş değerleri de analiz et
                ]
        return entropy_results
    except Exception as e:
        logger.error(f"URL '{url}' analiz edilirken hata oluştu: {e}")
        return { # Hata durumunda da tutarlı bir yapı dön
            "url": url,
            "error": str(e),
            "path_entropy": None, # veya 0.0
            "path_segments_entropy": [],
            "query_string_entropy": None, # veya 0.0
            "query_params_entropy": {}
        }

# Ana fonksiyon (web uygulamasından çağrılacak)
def run_entropy_analysis(input_filepath: str, output_filepath: str, verbose: bool = False) -> bool:
    """
    Girdi dosyasındaki URL'leri okur, her birinin entropisini analiz edip
    sonuçları çıktı dosyasına JSON formatında yazar.
    
    Args:
        input_filepath (str): Linkleri içeren dosyanın yolu.
        output_filepath (str): Entropi analiz sonuçlarının JSON olarak yazılacağı dosyanın yolu.
        verbose (bool): Ayrıntılı loglama için.
        
    Returns:
        bool: İşlem başarılıysa True, değilse False.
    """
    if verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose mod aktif edildi (entropy_analyzer).")
    else:
        logger.setLevel(logging.INFO)

    logger.info(f"URL dosyası okunuyor: {input_filepath}")
    all_results: List[Dict[str, Any]] = []
    urls_to_analyze: List[str] = []

    if not os.path.exists(input_filepath):
        logger.error(f"Girdi dosyası bulunamadı: {input_filepath}")
        return False

    try:
        with open(input_filepath, 'r', encoding='utf-8') as f:
            urls_to_analyze = [line.strip() for line in f if line.strip()]
    except IOError as e:
        logger.error(f"Girdi dosyası '{input_filepath}' okunurken hata: {e}")
        return False
    except Exception as e:
        logger.exception(f"Girdi dosyası okunurken beklenmedik hata: {e}")
        return False

    if not urls_to_analyze:
        logger.warning(f"Girdi dosyasında işlenecek URL bulunamadı: {input_filepath}")
        # Boş dosya için çıktı dosyası oluşturup bilgi yazılabilir.
        try:
            with open(output_filepath, 'w', encoding='utf-8') as outfile:
                json.dump([], outfile, indent=4, ensure_ascii=False) # Boş JSON listesi yaz
            logger.info(f"Girdide URL olmadığı için boş entropi analiz raporu şuraya kaydedildi: {output_filepath}")
            return True # Hata değil, işlem tamamlandı (boş da olsa)
        except IOError as e:
            logger.error(f"Boş sonuç dosyasına yazılırken hata oluştu ('{output_filepath}'): {e}")
            return False

    logger.info(f"Toplam {len(urls_to_analyze)} URL entropi analizi için işlenecek...")
    processed_count = 0
    for i, url in enumerate(urls_to_analyze):
        logger.debug(f"Entropi analizi yapılıyor ({i+1}/{len(urls_to_analyze)}): {url}")
        analysis_result = analyze_url_entropy(url)
        if analysis_result: # analyze_url_entropy her zaman bir dict döndürür
            all_results.append(analysis_result)
            processed_count +=1

    try:
        with open(output_filepath, 'w', encoding='utf-8') as outfile:
            json.dump(all_results, outfile, indent=4, ensure_ascii=False)
        logger.info(f"Entropi analiz sonuçları ({processed_count} URL işlendi) şuraya kaydedildi: {output_filepath}")
        return True
    except IOError as e:
        logger.error(f"Sonuç dosyasına yazılırken hata oluştu ('{output_filepath}'): {e}")
        return False
    except Exception as e:
        logger.exception(f"Sonuçlar JSON'a çevrilirken/yazılırken beklenmedik hata: {e}")
        return False

# Web uygulamasından çağrılırken bu __main__ bloğu çalışmayacaktır.
# if __name__ == "__main__":
    # Script'in bulunduğu dizini al
    # script_dir = os.path.dirname(os.path.abspath(__file__))

    # Varsayılan girdi ve çıktı dosyalarının tam yollarını oluştur
    # default_input_path = os.path.join(script_dir, DEFAULT_INPUT_FILENAME)
    # default_output_path = os.path.join(script_dir, DEFAULT_OUTPUT_FILENAME)
    # logger.info(f"Varsayılan girdi dosyası kullanılacak: {default_input_path}")
    # logger.info(f"Varsayılan çıktı dosyası kullanılacak: {default_output_path}")

    # process_link_file(default_input_path, default_output_path)

# Örnek Çağrı (Flask uygulamasından veya başka bir scriptten):
# from analysis import entropy_analyzer
#
# input_path = "/path/to/scan_results/unique_scan_id/bulunan_linkler.txt"
# output_path = "/path/to/scan_results/unique_scan_id/url_entropi_analizi.json"
# enable_verbose_logging = True
#
# success = entropy_analyzer.run_entropy_analysis(
# input_filepath=input_path,
# output_filepath=output_path,
# verbose=enable_verbose_logging
# )
# if success:
# print("Entropi analizi başarıyla tamamlandı.")
# else:
# print("Entropi analizi sırasında bir hata oluştu.")