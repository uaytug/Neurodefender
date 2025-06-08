# NeuroDefender - Kod Açıklamaları

<div align="center">
  <img src="public/neurodefender_logo.png" alt="NeuroDefender Logo" width="200"/>
  
  **Yapay Zeka Destekli Saldırı Tespit ve Önleme Sistemi**
</div>

## 🏗️ Proje Yapısı

```
neurodefender/
├── src/                    # React frontend kaynak kodları
├── src-tauri/             # Tauri/Rust backend kaynak kodları
├── public/                # Statik dosyalar
├── rules/                 # Güvenlik kuralları
└── dist/                  # Derleme çıktıları
```

## 📁 Frontend Kodları (React/TypeScript)

### 🚀 Ana Giriş Noktası

#### `src/main.tsx`
```typescript
// React uygulamasının başlangıç noktası
// ReactDOM ile App bileşenini render eder
// BrowserRouter ile yönlendirme sistemini başlatır
```

### 📱 Ana Bileşenler

#### `src/App.tsx`
- **Amaç**: Uygulamanın ana bileşeni ve yönlendirme merkezi
- **İçerik**: 
  - React Router ile sayfa yönlendirmeleri
  - Navbar bileşenini her sayfada gösterir
  - Tüm sayfa bileşenlerini yönetir

#### `src/Navbar.tsx`
- **Amaç**: Üst navigasyon çubuğu
- **Özellikler**:
  - Logo ve uygulama adı
  - Sayfa bağlantıları (Dashboard, Alerts, Reports, vb.)
  - Aktif sayfa vurgulama
  - Responsive tasarım

#### `src/Dashboard.tsx`
- **Amaç**: Ana kontrol paneli
- **İçerik**:
  - Gerçek zamanlı sistem metrikleri (CPU, RAM, Ağ)
  - Güvenlik skoru göstergesi
  - Tehdit istatistikleri
  - Hızlı eylem kartları
  - Canlı grafik ve görselleştirmeler

#### `src/Alerts.tsx`
- **Amaç**: Güvenlik uyarıları yönetimi
- **Özellikler**:
  - Uyarı listesi (Yüksek/Orta/Düşük öncelik)
  - Filtreleme ve arama
  - Toplu işlemler
  - Uyarı detayları modalı
  - Uyarı yanıtlama aksiyonları

#### `src/Reports.tsx`
- **Amaç**: Güvenlik raporları oluşturma
- **Özellikler**:
  - Rapor türü seçimi (Özet/Detaylı/Uyumluluk)
  - Tarih aralığı seçimi
  - Format seçimi (PDF/CSV/JSON/HTML)
  - Rapor önizleme
  - İndirme ve paylaşma

#### `src/Settings.tsx`
- **Amaç**: Uygulama ayarları
- **Sekmeler**:
  - **Genel**: Tema, dil, otomatik güncelleme
  - **Algılama**: Hassasiyet, ML ayarları
  - **Ağ**: Firewall, VPN, DDoS koruması
  - **Bildirimler**: E-posta, masaüstü, ses ayarları
  - **Gelişmiş**: Performans modu, loglama

#### `src/FAQ.tsx`
- **Amaç**: Sık sorulan sorular
- **Özellikler**:
  - Kategorilere ayrılmış sorular
  - Arama fonksiyonu
  - Genişletilebilir cevaplar
  - Kopyalama butonu

#### `src/AboutUs.tsx`
- **Amaç**: Hakkımızda sayfası
- **İçerik**:
  - Şirket bilgileri
  - Takım üyeleri
  - Teknoloji stack'i
  - İletişim bilgileri

### 🔧 Servis Katmanı

#### `src/services/api.ts`
- **Amaç**: Backend API iletişimi
- **Fonksiyonlar**:
  ```typescript
  // Sistem bilgilerini getirir
  getSystemInfo()
  
  // Uyarıları yönetir
  getAlerts(), deleteAlert(), bulkDeleteAlerts()
  
  // Rapor oluşturur
  generateReport()
  
  // Ayarları yönetir
  getSettings(), updateSettings()
  ```

#### `src/services/tauri-api.ts`
- **Amaç**: Tauri komutlarını çağırır
- **Fonksiyonlar**:
  ```typescript
  // Rust backend'e komut gönderir
  invoke('get_system_info')
  invoke('generate_report')
  invoke('update_settings')
  ```

#### `src/services/tray-events.ts`
- **Amaç**: Sistem tepsisi olayları
- **Özellikler**:
  - Tray menü tıklamaları
  - Bildirim yönetimi
  - Pencere kontrolü

#### `src/services/sysinfo.ts`
- **Amaç**: Sistem bilgisi yardımcıları
- **Fonksiyonlar**:
  - CPU kullanımı hesaplama
  - Bellek kullanımı formatlama
  - Ağ trafiği gösterimi

## 📦 Backend Kodları (Rust/Tauri)

### 🦀 Ana Dosyalar

#### `src-tauri/src/main.rs`
```rust
// Tauri uygulamasının giriş noktası
// Windows'ta konsol penceresini gizler
// lib.rs'deki run() fonksiyonunu çağırır
```
- **İşlevi**: Uygulamanın başlangıç noktası. Windows'ta release modunda konsol penceresinin açılmasını engeller.

#### `src-tauri/src/lib.rs`
- **Amaç**: Ana kütüphane ve Tauri yapılandırması
- **Detaylı İçerik**:
  - Tüm Tauri komutlarının tanımlandığı merkezi dosya
  - Modül organizasyonu ve import'lar
  - Uygulama başlatma mantığı (`run()` fonksiyonu)
  - API endpoint'lerinin Tauri'ye kaydedilmesi
  - Sistem tepsisi başlatma
  - Global state yönetimi
  - Event listener'ların kurulumu

#### `src-tauri/src/config_manager.rs`
- **Amaç**: Uygulama konfigürasyonlarının merkezi yönetimi
- **Detaylı İşlevler**:
  - JSON formatında ayarları okuma/yazma
  - Varsayılan konfigürasyon değerleri
  - Ayar validasyonu ve tip kontrolü
  - Konfigürasyon dosyası versiyonlama
  - Hot-reload desteği
  - Ayar değişikliklerini dinleme

#### `src-tauri/src/robustness.rs`
- **Amaç**: Uygulama güvenilirliği ve hata toleransı
- **Detaylı İşlevler**:
  - Kritik hataları yakalama ve kurtarma
  - Otomatik yedekleme sistemi
  - Sistem sağlığı kontrolü (health checks)
  - Crash raporlama
  - Otomatik yeniden başlatma
  - Bellek sızıntısı tespiti
  - Performans metrikleri toplama

### 📂 API Modülü (`src-tauri/src/api/`)

#### `api/mod.rs`
- **Amaç**: API modülünün ana dosyası
- **İçerik**: Alt modülleri dışa aktarır

#### `api/routes.rs`
- **Amaç**: HTTP API route tanımlamaları
- **Detaylı İçerik**:
  - REST endpoint'lerinin tanımlanması
  - Route parametreleri ve middleware'ler
  - CORS ayarları
  - Rate limiting kuralları
  - API versiyonlama
  - Request/Response loglama

#### `api/handlers/mod.rs`
- **Amaç**: Handler modüllerini organize eder
- **İçerik**: Tüm handler modüllerini dışa aktarır

#### `api/handlers/dashboard.rs`
- **Amaç**: Dashboard API endpoint'leri
- **Fonksiyonlar**:
  - `get_system_info()`: CPU, RAM, disk kullanımı
  - `get_network_stats()`: Ağ trafiği istatistikleri
  - `get_security_score()`: Güvenlik skoru hesaplama
  - `get_threat_summary()`: Tehdit özeti
  - `get_recent_activities()`: Son aktiviteler

#### `api/handlers/alerts.rs`
- **Amaç**: Uyarı yönetimi API'si
- **Fonksiyonlar**:
  - `get_alerts()`: Uyarı listesi (filtreleme, sayfalama)
  - `get_alert_by_id()`: Tekil uyarı detayı
  - `create_alert()`: Yeni uyarı oluşturma
  - `update_alert()`: Uyarı güncelleme
  - `delete_alert()`: Uyarı silme
  - `bulk_operations()`: Toplu işlemler
  - `mark_as_read()`: Okundu işaretleme

#### `api/handlers/reports.rs`
- **Amaç**: Rapor oluşturma ve yönetimi
- **Fonksiyonlar**:
  - `generate_report()`: Rapor oluşturma (PDF/CSV/JSON/HTML)
  - `get_report_templates()`: Rapor şablonları
  - `schedule_report()`: Zamanlanmış raporlar
  - `get_report_history()`: Rapor geçmişi
  - `export_report()`: Rapor dışa aktarma
  - `email_report()`: E-posta ile gönderme

#### `api/handlers/settings.rs`
- **Amaç**: Ayar yönetimi API'si
- **Fonksiyonlar**:
  - `get_settings()`: Mevcut ayarları getir
  - `update_settings()`: Ayarları güncelle
  - `reset_settings()`: Varsayılana dön
  - `export_settings()`: Ayarları dışa aktar
  - `import_settings()`: Ayarları içe aktar
  - `validate_settings()`: Ayar doğrulama

#### `api/handlers/prevention.rs`
- **Amaç**: Önleme sistemi API'si
- **Fonksiyonlar**:
  - `get_blocked_ips()`: Engellenmiş IP listesi
  - `block_ip()`: IP engelleme
  - `unblock_ip()`: IP engeli kaldırma
  - `get_firewall_rules()`: Firewall kuralları
  - `update_firewall_rules()`: Kural güncelleme

#### `api/handlers/faq.rs`
- **Amaç**: SSS API endpoint'leri
- **Fonksiyonlar**:
  - `get_faq_categories()`: Kategori listesi
  - `get_faq_items()`: SSS öğeleri
  - `search_faq()`: SSS arama

### 📂 Capture Modülü (`src-tauri/src/capture/`)

#### `capture/mod.rs`
- **Amaç**: Capture modülünün organizasyonu
- **İçerik**: Alt modülleri dışa aktarır

#### `capture/pcap.rs`
- **Amaç**: Paket yakalama motoru
- **Detaylı İşlevler**:
  - Ağ arayüzlerini listeleme ve seçme
  - Pcap kütüphanesi ile paket yakalama
  - BPF (Berkeley Packet Filter) filtreleri
  - Paket tamponu yönetimi
  - Yakalama istatistikleri
  - Pcap dosyası okuma/yazma

#### `capture/packet.rs`
- **Amaç**: Paket ayrıştırma ve analiz
- **Detaylı İşlevler**:
  - Ethernet frame ayrıştırma
  - IP paket analizi (IPv4/IPv6)
  - TCP/UDP segment analizi
  - Uygulama katmanı protokolleri (HTTP, DNS, vb.)
  - Paket metadata çıkarma
  - Checksum doğrulama

#### `capture/analyzer.rs`
- **Amaç**: Trafik analiz motoru
- **Detaylı İşlevler**:
  - Gerçek zamanlı trafik analizi
  - Protokol dağılımı hesaplama
  - Bant genişliği kullanımı
  - Anormal trafik tespiti
  - DPI (Deep Packet Inspection)
  - Trafik pattern tanıma

### 📂 Detection Modülü (`src-tauri/src/detection/`)

#### `detection/mod.rs`
- **Amaç**: Detection modülü organizasyonu
- **İçerik**: Alt modülleri ve trait'leri dışa aktarır

#### `detection/engine.rs`
- **Amaç**: Ana tehdit algılama motoru
- **Detaylı İşlevler**:
  - Çoklu algılama yöntemlerini koordine etme
  - Tehdit skorlama algoritması
  - Algılama pipeline yönetimi
  - False positive azaltma
  - Algılama kuralı önceliklendirme
  - Real-time ve batch analiz modları

#### `detection/signatures.rs`
- **Amaç**: İmza tabanlı tehdit algılama
- **Detaylı İşlevler**:
  - Malware imza veritabanı
  - Yara kuralları entegrasyonu
  - İmza güncelleme sistemi
  - Hash tabanlı algılama (MD5, SHA256)
  - Pattern matching algoritmaları
  - İmza performans optimizasyonu

#### `detection/rules.rs`
- **Amaç**: Kural tabanlı algılama sistemi
- **Detaylı İşlevler**:
  - Snort/Suricata kural formatı desteği
  - Özel kural dili parser'ı
  - Kural öncelik ve kategorizasyonu
  - Dinamik kural yükleme
  - Kural test ve validasyon
  - Performans profiling

#### `detection/mlengine/`
- **Amaç**: Makine öğrenmesi algılama motoru
- **Alt Modüller**:
  - Model yükleme ve yönetimi
  - Feature extraction
  - Anomali algılama algoritmaları
  - Model güncelleme sistemi
  - Prediction API'si

### 📂 Prevention Modülü (`src-tauri/src/prevention/`)

#### `prevention/mod.rs`
- **Amaç**: Prevention modülü koordinasyonu
- **İçerik**: Alt modülleri organize eder ve dışa aktarır

#### `prevention/actions.rs`
- **Amaç**: Tehdit yanıt aksiyonları
- **Detaylı İşlevler**:
  - Otomatik yanıt stratejileri
  - Aksiyon öncelik sıralaması
  - Rollback mekanizması
  - Aksiyon loglama
  - Kullanıcı onayı gerektiren aksiyonlar
  - Aksiyon şablonları

#### `prevention/blocker.rs`
- **Amaç**: IP ve port engelleme sistemi
- **Detaylı İşlevler**:
  - IP engelleme/kaldırma
  - Port engelleme
  - Geçici/kalıcı engelleme
  - Whitelist/blacklist yönetimi
  - Coğrafi IP engelleme
  - Engelleme istatistikleri

#### `prevention/firewall.rs`
- **Amaç**: Firewall entegrasyonu
- **Detaylı İşlevler**:
  - Windows Firewall API entegrasyonu
  - iptables/nftables (Linux) desteği
  - macOS pf firewall entegrasyonu
  - Kural oluşturma/silme
  - Firewall durumu izleme
  - Kural çakışma kontrolü

#### `prevention/connection_tracker.rs`
- **Amaç**: Bağlantı takip sistemi
- **Detaylı İşlevler**:
  - Aktif bağlantıları izleme
  - Bağlantı yaşam döngüsü takibi
  - State tablosu yönetimi
  - Anormal bağlantı tespiti
  - Bağlantı limitleri
  - NAT takibi

#### `prevention/rate_limiter.rs`
- **Amaç**: Hız sınırlama ve DDoS koruması
- **Detaylı İşlevler**:
  - Token bucket algoritması
  - Per-IP rate limiting
  - API endpoint koruması
  - Burst trafiği yönetimi
  - Adaptif rate limiting
  - DDoS pattern algılama

#### `prevention/threat_intelligence.rs`
- **Amaç**: Tehdit istihbaratı entegrasyonu
- **Detaylı İşlevler**:
  - Threat feed entegrasyonu
  - IP reputation kontrolü
  - Domain reputation
  - Hash reputation
  - Threat intelligence güncelleme
  - IOC (Indicators of Compromise) yönetimi

### 📂 Services Modülü (`src-tauri/src/services/`)

#### `services/mod.rs`
- **Amaç**: Servis modüllerini organize eder

#### `services/monitor_service.rs`
- **Amaç**: Sistem ve ağ izleme servisi
- **Detaylı İşlevler**:
  - Gerçek zamanlı sistem metrikleri
  - Ağ trafiği monitörleme
  - Process monitörleme
  - Servis durumu kontrolü
  - Performans alarmları
  - Metrik aggregation
  - Grafik verisi hazırlama

#### `services/alert_service.rs`
- **Amaç**: Uyarı yönetim servisi
- **Detaylı İşlevler**:
  - Uyarı oluşturma ve yönetimi
  - Uyarı önceliklendirme
  - Bildirim gönderme
  - Uyarı gruplama
  - Uyarı korelasyonu
  - Escalation yönetimi

#### `services/report_service.rs`
- **Amaç**: Rapor oluşturma servisi
- **Detaylı İşlevler**:
  - Rapor template engine
  - PDF/HTML/CSV oluşturma
  - Grafik ve chart oluşturma
  - Rapor zamanlama
  - Rapor dağıtımı
  - Rapor arşivleme

#### `services/auth_service.rs`
- **Amaç**: Kimlik doğrulama ve yetkilendirme
- **Detaylı İşlevler**:
  - Kullanıcı kimlik doğrulama
  - Token yönetimi
  - Rol tabanlı erişim kontrolü
  - Session yönetimi
  - API key yönetimi
  - Audit logging

### 📂 Storage Modülü (`src-tauri/src/storage/`)

#### `storage/mod.rs`
- **Amaç**: Storage katmanı organizasyonu
- **İçerik**: Veritabanı bağlantısı ve repository'leri yönetir

#### `storage/db.rs`
- **Amaç**: Veritabanı bağlantı yönetimi
- **Detaylı İşlevler**:
  - SQLite bağlantı havuzu
  - Migration yönetimi
  - Transaction yönetimi
  - Bağlantı retry logic
  - Query optimization
  - Backup/restore

#### `storage/models/`
- **Amaç**: Veritabanı model tanımlamaları
- **İçerik**:
  - Alert modeli
  - Report modeli
  - Settings modeli
  - User modeli
  - Log modeli

#### `storage/repositories/`
- **Amaç**: Veri erişim katmanı
- **Repository'ler**:
  - AlertRepository
  - ReportRepository
  - SettingsRepository
  - LogRepository
  - Her biri CRUD operasyonları sağlar

### 📂 Tray Module (`src-tauri/src/tray_module/`)

#### `tray_module/mod.rs`
- **Amaç**: Tray modülü organizasyonu

#### `tray_module/tray_initializer.rs`
- **Amaç**: Sistem tepsisi başlatma ve yönetimi
- **Detaylı İşlevler**:
  - Tray ikonu oluşturma
  - Dinamik menü oluşturma
  - Menü event handler'ları
  - Tray tooltip güncelleme
  - Platform-specific tray özellikleri
  - Tray animasyonları

#### `tray_module/notifications.rs`
- **Amaç**: Masaüstü bildirim sistemi
- **Detaylı İşlevler**:
  - Native bildirim gönderme
  - Bildirim öncelik seviyeleri
  - Bildirim sesi yönetimi
  - Bildirim geçmişi
  - Click handler'ları
  - Platform-specific özellikler

### 📂 Utils Modülü (`src-tauri/src/utils/`)

#### `utils/mod.rs`
- **Amaç**: Yardımcı fonksiyonları organize eder

#### `utils/config.rs`
- **Amaç**: Konfigürasyon yardımcıları
- **Detaylı İşlevler**:
  - Konfigürasyon dosya yolu yönetimi
  - Environment variable okuma
  - Konfigürasyon merge logic
  - Tip dönüşümleri
  - Validasyon helper'ları

#### `utils/error.rs`
- **Amaç**: Hata yönetimi ve custom error tipleri
- **Detaylı İşlevler**:
  - Custom error enum'ları
  - Error conversion trait'leri
  - Error chain yönetimi
  - User-friendly error mesajları
  - Error logging ve raporlama

#### `utils/logger.rs`
- **Amaç**: Loglama sistemi
- **Detaylı İşlevler**:
  - Log level yönetimi
  - Dosya ve konsol loglama
  - Log rotation
  - Structured logging
  - Performance logging
  - Remote log gönderme

### 📂 Popup Modülü (`src-tauri/src/popup/`)

#### `popup/mod.rs`
- **Amaç**: Popup pencere yönetimi
- **Detaylı İşlevler**:
  - Uyarı popup'ları oluşturma
  - Popup pozisyon yönetimi
  - Auto-close timer'ları
  - Popup animasyonları
  - Click-through özellikleri

## ⚙️ Konfigürasyon Dosyaları

### `package.json`
- Node.js bağımlılıkları
- Proje scriptleri
- React ve Tauri versiyonları

### `src-tauri/Cargo.toml`
- Rust bağımlılıkları
- Tauri özellikleri
- Derleme ayarları

### `src-tauri/tauri.conf.json`
- Tauri uygulama ayarları
- Pencere konfigürasyonu
- Güvenlik politikaları

### `vite.config.ts`
- Vite build ayarları
- React plugin'i
- Development server

### `tsconfig.json`
- TypeScript derleyici ayarları
- Tip tanımlamaları
- Module çözümleme

## 🎨 Stil Dosyaları

### `src/styles/`
- **App.css**: Ana uygulama stilleri
- **Dashboard.css**: Kontrol paneli özel stilleri
- **Alerts.css**: Uyarı sayfası stilleri
- Diğer bileşen-özel CSS dosyaları

## 🔧 Yardımcı Dosyalar

### `.gitignore`
- Git'in takip etmeyeceği dosyalar
- node_modules/, dist/, target/

### `index.html`
- React uygulamasının HTML şablonu
- Root div elementi
- Meta tag'ler

## 🚀 Çalıştırma Komutları

```bash
# Geliştirme
npm run dev          # React dev server
npm run tauri dev    # Tauri dev modu

# Derleme
npm run build        # React build
npm run tauri build  # Desktop uygulama

# Test
npm run test         # Test suite
npm run lint         # Kod kalite kontrolü
```

## 📝 Önemli Notlar

1. **Frontend-Backend İletişimi**: Tauri'nin `invoke` sistemi kullanılır
2. **Güvenlik**: Tüm hassas işlemler Rust backend'de yapılır
3. **Performans**: React için lazy loading, Rust için async/await
4. **Hata Yönetimi**: Try-catch blokları ve Result<T, E> tipi

---

<div align="center">
  <p>NeuroDefender - Dijital varlıklarınızı AI ile koruyoruz</p>
</div> 