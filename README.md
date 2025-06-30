# Gazinetix - Web Güvenlik Analiz Sistemi

![image](https://github.com/user-attachments/assets/f91d2ea9-0b6d-412c-8f6f-a629c2cad8f6)
![image](https://github.com/user-attachments/assets/c36328f3-dede-4a35-beb9-6790ca882878)
![image](https://github.com/user-attachments/assets/9dc8518d-d123-4a9f-be2a-e4859bb5aafe)


**Gazinetix**, web uygulamalarındaki yaygın güvenlik açıklarını (SQL Enjeksiyonu, XSS vb.) tespit etmek amacıyla geliştirilmiş modüler bir güvenlik tarama aracıdır. Proje, bir web sitesini tarayarak linkleri keşfeder, statik ve dinamik analiz tekniklerini birleştirerek potansiyel zafiyetleri arar ve bulguları raporlar. Sistem, hem komut satırı araçları olarak hem de kullanıcı dostu bir web arayüzü üzerinden çalıştırılmak üzere tasarlanmıştır.

Bu proje, Gazi Üniversitesi BMT360 Bilgisayar Projesi Tasarımı dersi kapsamında geliştirilmiştir.

## ✨ Temel Özellikler

*   **🔗 Kapsamlı Link Keşfi (Crawler):** Belirlenen bir hedef URL'den başlayarak, belirtilen derinliğe kadar site haritasını çıkarır ve iç linkleri toplar.
*   **🧩 Modüler Analiz Akışı:**
    *   **Link Analizcisi (`analyzer.py`):** Keşfedilen linkleri statik/dinamik olarak sınıflandırır ve GET parametrelerini çıkarır.
    *   **Statik URL Analizi (`static_analysis.py`):** URL string'lerinde bilinen zararlı kalıpları (SQLi, XSS, Command Injection, Directory Traversal) regex ile arar.
    *   **Entropi Analizi (`entropy_analyzer.py`):** URL yapılarının Shannon entropisini hesaplayarak anormal veya şüpheli görünen linkleri belirler.
    *   **Aktif Tarayıcı (`scanner.py`):** Dinamik URL'lerin GET parametrelerine önceden tanımlanmış SQLi ve XSS payload'larını enjekte ederek aktif güvenlik testleri yapar.
*   **💻 Kullanıcı Dostu Web Arayüzü:** Flask ile geliştirilmiş web arayüzü sayesinde kullanıcılar, tarama işlemlerini kolayca başlatabilir, parametreleri yönetebilir ve sonuçları görüntüleyebilir.
*   **📂 Düzenli Raporlama:** Her tarama işlemi için benzersiz bir ID oluşturulur ve tüm çıktılar (keşfedilen linkler, analizler, zafiyet raporu, entropi analizi) bu ID'ye ait ayrı bir klasörde düzenli olarak saklanır.
*   **⚙️ Esnek ve Genişletilebilir:** Modüler yapısı sayesinde, gelecekte yeni zafiyet türleri, analiz teknikleri veya farklı programlama dilleri için destek eklemek kolaydır.

## 🛠️ Kurulum

Projeyi yerel makinenizde çalıştırmak için aşağıdaki adımları izleyin.

**Gereksinimler:**
*   Python 3.10+
*   pip (Python paket yöneticisi)

**Adımlar:**

1.  **Projeyi Klonlayın:**
    ```bash
    git clone https://github.com/KULLANICI_ADINIZ/Gazinetix.git
    cd Gazinetix
    ```

2.  **Sanal Ortam Oluşturun ve Aktifleştirin:**
    *   Bu, projenin bağımlılıklarını sisteminizin genel Python kurulumundan izole tutar.
    ```bash
    # Sanal ortamı oluştur
    python -m venv venv

    # Sanal ortamı aktifleştir
    # Windows (PowerShell) için:
    .\venv\Scripts\Activate.ps1
    # Windows (CMD) için:
    venv\Scripts\activate.bat
    # MacOS / Linux için:
    source venv/bin/activate
    ```
    *Eğer PowerShell'de "execution policy" hatası alırsanız, Yönetici olarak açtığınız bir PowerShell'de şu komutu çalıştırın: `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`*

3.  **Gerekli Kütüphaneleri Yükleyin:**
    ```bash
    pip install -r requirements.txt
    ```
    *Not: `requirements.txt` dosyanız yoksa, aşağıdaki komutla kütüphaneleri manuel olarak yükleyebilirsiniz:*
    ```bash
    pip install Flask requests beautifulsoup4
    ```

## 🚀 Kullanım

### Web Arayüzü Üzerinden

1.  **Flask Sunucusunu Başlatın:**
    *   Projenin ana dizinindeyken ve sanal ortam aktifken terminalde şu komutu çalıştırın:
    ```bash
    python app.py
    ```

2.  **Tarayıcıda Açın:**
    *   Bir web tarayıcısı açın ve adres çubuğuna `http://127.0.0.1:5000/` yazın.

3.  **Taramayı Başlatın:**
    *   Açılan arayüzdeki forma taranacak hedef URL'yi ve tarama derinliğini girin.
    *   "Taramayı Başlat" butonuna tıklayın.
    *   Tarama arka planda başlayacaktır. Size sunulan "Sonuçları Görüntüle" linkine tıklayarak tarama durumunu ve tamamlandığında raporları görebilirsiniz.

### Komut Satırı Üzerinden (Modülleri Ayrı Ayrı Çalıştırmak İçin)

Projenin temel modülleri komut satırından da çalıştırılabilir (bu, geliştirme ve hata ayıklama için kullanışlıdır).

*   **Crawler'ı Çalıştırmak:**
    ```bash
    python scripts/crawler.py https://hedefsite.com -d 2 -o bulunan.txt
    ```
    Daha fazla parametre için `python scripts/crawler.py --help` komutunu kullanabilirsiniz.


## 🚧 Gelecek Çalışmalar ve Geliştirme Fikirleri

Bu proje, daha kapsamlı bir güvenlik aracına dönüşmek için sağlam bir temel sunmaktadır. Gelecek için planlanan bazı önemli geliştirmeler:

*   **🤖 Yapay Zekâ Destekli Düzeltme Önerileri:** Tespit edilen zafiyetler için (LLM'ler veya ML modelleri kullanarak) akıllı kod düzeltme önerileri sunmak.
*   **🎯 Genişletilmiş Zafiyet Kapsamı:** POST istekleri, HTTP başlıkları, Çerezler gibi farklı giriş vektörlerini test etme ve Command Injection, SSRF gibi diğer OWASP Top 10 zafiyetlerini ekleme.
*   **⚡️ Anlık İlerleme Takibi:** Web arayüzünde WebSockets veya SSE kullanarak tarama ilerlemesini ve loglarını canlı olarak gösterme.
*   **⚙️ Ölçeklenebilir Görev Yönetimi:** Arka plan görevleri için `threading` yerine Celery ve Redis/RabbitMQ kullanarak daha sağlam ve ölçeklenebilir bir yapıya geçme.
*   **👤 Kullanıcı Yönetimi:** Kullanıcı hesapları ve tarama geçmişi gibi özellikler ekleme.

## 🤝 Katkıda Bulunma

Bu proje bir öğrenme ve geliştirme projesidir. Katkıda bulunmak, hata bildirmek veya öneri sunmak isterseniz lütfen bir "Issue" açmaktan veya "Pull Request" göndermekten çekinmeyin.
