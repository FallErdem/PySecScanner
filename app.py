from flask import Flask, render_template, request, url_for, redirect, flash
import os
import uuid
import threading
# import time # şu annda gerek yok run_full_scan_background ile çakıştı

# 'scripts' klasöründeki modülleri import etmek için:
# Bu importların çalışması için 'scripts' klasörünün içinde boş bir '__init__.py' dosyası eklemek gerek TODO
from scripts import crawler
from scripts import analyzer
from scripts import entropy_analyzer
from scripts import scanner
#TODO
# Not: analyzer.py içindeki 'from .analysis.static_analysis import analiz_et as static_analyze_url'
# importunun doğru çalıştığını kontrol et (scripts/analysis/ klasöründe __init__.py ve static_analysis.py).

app = Flask(__name__)
app.secret_key = "BURAYA_COK_DAHA_GUVENLI_BIR_ANAHTAR_GIRIN_ORNEGIN_OS.URANDOM(24)" # Flash mesajları için gerekli

# Her tarama için sonuçların saklanacağı klasör
SCANS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_outputs")
if not os.path.exists(SCANS_DIR):
    os.makedirs(SCANS_DIR)

# Ana sayfa: URL ve derinlik girilecek yer
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

# Tarama işlemini başlatan yer
@app.route('/scan', methods=['POST'])
def start_scan_route():
    target_url = request.form.get('target_url', '').strip() # strip() ile baş/son boşlukları al
    
    # Gelişmiş ayarları formdan al, varsayılan değer atama kısmo
    try:
        scan_depth = int(request.form.get('scan_depth', 1))
        if scan_depth < 0: scan_depth = 0 # Negatif derinlik olmasın
    except ValueError:
        scan_depth = 1
    
    try:
        crawl_timeout = int(request.form.get('timeout', 10))
        if crawl_timeout < 1: crawl_timeout = 10 # Minimum timeout
    except ValueError:
        crawl_timeout = 10

    try:
        crawl_sleep_time = float(request.form.get('sleep_time', 0.5))
        if crawl_sleep_time < 0: crawl_sleep_time = 0.1 # Minimum sleep
    except ValueError:
        crawl_sleep_time = 0.5

    # Temel URL doğrulaması
    if not target_url:
        flash('Lütfen bir hedef URL girin.', 'danger')
        return redirect(url_for('index'))
    
    if not (target_url.startswith('http://') or target_url.startswith('https://')):
        flash('Lütfen geçerli bir URL girin (http:// veya https:// ile başlamalı).', 'warning')
        return redirect(url_for('index'))

    scan_id = str(uuid.uuid4())
    scan_output_dir = os.path.join(SCANS_DIR, scan_id)
    os.makedirs(scan_output_dir, exist_ok=True)

    bulunan_linkler_file = os.path.join(scan_output_dir, "bulunan_linkler.txt")
    analyzed_links_file = os.path.join(scan_output_dir, "analyzed_links.txt")
    entropy_file = os.path.join(scan_output_dir, "url_entropi_analizi.json")
    report_file = os.path.join(scan_output_dir, "vulnerability_report.txt")
    status_file = os.path.join(scan_output_dir, "scan_status.txt") # Durum dosyası

    # Durum dosyasını "BAŞLATILIYOR" olarak işaretle
    try:
        with open(status_file, "w", encoding='utf-8') as f:
            f.write("BAŞLATILIYOR")
    except Exception as e:
        app.logger.error(f"Durum dosyası yazılamadı [{scan_id}]: {e}")


    scan_thread = threading.Thread(target=run_full_scan_background, 
                                   args=(target_url, scan_depth, 
                                         bulunan_linkler_file, analyzed_links_file, 
                                         entropy_file, report_file, status_file, scan_id,
                                         crawl_timeout, crawl_sleep_time))
    scan_thread.start()

    # Kullanıcıyı HTML sayfasına yönlendir
    return render_template('scan_started.html', scan_id=scan_id, target_url=target_url)


def run_full_scan_background(target_url, scan_depth, 
                             bulunan_linkler_file, analyzed_links_file, 
                             entropy_file, report_file, status_file, scan_id,
                             crawl_timeout_param, crawl_sleep_time_param):
    
    current_app_logger = app.logger # Flask logger'ını kullanmak için
    current_app_logger.info(f"[{scan_id}] Arka plan tarama görevi başlıyor: {target_url}")
    
    def update_status(message):
        try:
            with open(status_file, "a", encoding='utf-8') as f: # 'a' (append) modu ile ekle
                f.write(f"\n{message}")
            current_app_logger.info(f"[{scan_id}] Durum: {message}")
        except Exception as e:
            current_app_logger.error(f"Durum dosyasına yazılırken hata [{scan_id}]: {e}")

    update_status("Crawler başlatılıyor...")
    try:
        crawler.crawl_site(
            base_url=target_url,
            max_depth=scan_depth,
            output_file_path=bulunan_linkler_file,
            verbose=True, # veya app.debug durumuna göre ayarla
            timeout=crawl_timeout_param,
            sleep_time=crawl_sleep_time_param
        )
        update_status(f"Crawler tamamlandı. Çıktı: {os.path.basename(bulunan_linkler_file)}")
    except Exception as e:
        update_status(f"HATA: Crawler - {e}")
        current_app_logger.error(f"[{scan_id}] Crawler hatası: {e}", exc_info=True)
        return

    update_status("Analyzer başlatılıyor...")
    try:
        success_analyzer = analyzer.run_link_analysis(
            input_file_path=bulunan_linkler_file,
            output_file_path=analyzed_links_file,
            verbose=True # veya app.debug
        )
        if success_analyzer:
            update_status(f"Analyzer tamamlandı. Çıktı: {os.path.basename(analyzed_links_file)}")
        else:
            update_status("HATA: Analyzer çalışırken sorun oluştu.")
            return # Analyzer başarısızsa devam etme
    except Exception as e:
        update_status(f"HATA: Analyzer - {e}")
        current_app_logger.error(f"[{scan_id}] Analyzer hatası: {e}", exc_info=True)
        return

    update_status("Entropy Analyzer başlatılıyor...")
    try:
        success_entropy = entropy_analyzer.run_entropy_analysis(
            input_filepath=bulunan_linkler_file, 
            output_filepath=entropy_file,
            verbose=True # veya app.debug
        )
        if success_entropy:
            update_status(f"Entropy Analyzer tamamlandı. Çıktı: {os.path.basename(entropy_file)}")
        else:
            update_status("UYARI: Entropy Analyzer çalışırken sorun oluştu, tarama devam ediyor.")
            # Bu adım kritik değilse devam edebilir
    except Exception as e:
        update_status(f"UYARI: Entropy Analyzer - {e}, tarama devam ediyor.")
        current_app_logger.warning(f"[{scan_id}] Entropy Analyzer hatası: {e}", exc_info=True)
        

    if os.path.exists(analyzed_links_file):
        update_status("Scanner başlatılıyor...")
        try:
            # Scanner'ın kendi timeout ve delay ayarları var, onlar da parametrik olabşlşr.
            # Şimdilik varsayılanlar var.
            success_scanner = scanner.run_vulnerability_scan(
                analyzed_file_path=analyzed_links_file,
                report_file_path=report_file,
                verbose=True # veya app.debug
                # request_timeout=SCANNER_TIMEOUT, # Gelecekte eklenebilir
                # request_delay=SCANNER_DELAY    # Gelecekte eklenebilir
            )
            if success_scanner:
                update_status(f"Scanner tamamlandı. Çıktı: {os.path.basename(report_file)}")
            else:
                update_status("HATA: Scanner çalışırken sorun oluştu.")
        except Exception as e:
            update_status(f"HATA: Scanner - {e}")
            current_app_logger.error(f"[{scan_id}] Scanner hatası: {e}", exc_info=True)
    else:
        update_status("Scanner atlandı çünkü analyzed_links.txt bulunamadı.")
    
    update_status("TAMAMLANDI")
    current_app_logger.info(f"[{scan_id}] Tüm tarama adımları tamamlandı.")


@app.route('/results/<scan_id>', methods=['GET'])
def show_results(scan_id):
    scan_output_dir = os.path.join(SCANS_DIR, scan_id)
    report_file_path = os.path.join(scan_output_dir, "vulnerability_report.txt")
    entropy_file_path = os.path.join(scan_output_dir, "url_entropi_analizi.json")
    status_file_path = os.path.join(scan_output_dir, "scan_status.txt") # Durum dosyası yolu
    
    report_content = "Zafiyet raporu henüz hazır değil veya bulunamadı."
    entropy_content = "Entropi raporu henüz hazır değil veya bulunamadı."
    scan_status_lines = ["Durum bilgisi bulunamadı."]

    if os.path.exists(report_file_path):
        try:
            with open(report_file_path, 'r', encoding='utf-8') as f:
                report_content = f.read()
        except Exception as e:
            report_content = f"Rapor okunurken hata: {e}"
            app.logger.error(f"Rapor okunurken hata [{scan_id}]: {e}")
    
    if os.path.exists(entropy_file_path):
        try:
            with open(entropy_file_path, 'r', encoding='utf-8') as f:
                entropy_content = f.read() 
        except Exception as e:
            entropy_content = f"Entropi raporu okunurken hata: {e}"
            app.logger.error(f"Entropi raporu okunurken hata [{scan_id}]: {e}")

    if os.path.exists(status_file_path):
        try:
            with open(status_file_path, 'r', encoding='utf-8') as f:
                scan_status_lines = f.read().strip().split('\n') # Her satırı ayrı eleman yap
        except Exception as e:
            scan_status_lines = [f"Durum dosyası okunurken hata: {e}"]
            app.logger.error(f"Durum dosyası okunurken hata [{scan_id}]: {e}")


    return render_template('results.html', 
                           scan_id=scan_id, 
                           report_content=report_content, 
                           entropy_content=entropy_content,
                           scan_status_lines=scan_status_lines) # Durum bilgisini template'e gönder

if __name__ == '__main__':
    # Flask'ın kendi logger'ını yapılandırma eklenebilir
    # app.logger.setLevel(logging.INFO) # veya DEBUG
    # handler = logging.StreamHandler() # Konsola log basmak için
    # handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    # app.logger.addHandler(handler)
    app.run(debug=True, use_reloader=False, threaded=True) # threaded=True, birden fazla isteği yönetmesi için