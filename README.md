# Reducing SOC False Alarms through a Human-AI Collaboration Model

> **Final Project — Security Operations Center (SOC)**
> Kelompok 4

---

## Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Team](#-team)
- [Tech Stack](#-tech-stack)
- [AI Model](#-ai-model--randomforest-classifier)
- [False Alarm Criteria](#-false-alarm-criteria)
- [Human-AI Collaboration Flow](#-human-ai-collaboration-flow)
- [Benchmark Metrics](#-benchmark-metrics)
- [Results & Analysis](#-results--analysis)
- [Repository Structure](#-repository-structure)
- [Setup & Installation](#-setup--installation)
- [Documentation](#-documentation)

---

## Overview

Security Operations Centers (SOC) often suffer from **alert fatigue** caused by the *"Better Safe Than Sorry"* philosophy — a high-sensitivity approach that prioritizes recall but generates overwhelming false positives. This project addresses that problem by building a **Human-AI Collaboration SOC system** that intelligently triages alerts, reducing false alarms without sacrificing detection accuracy.

### Background

The system focuses on **DDoS-like / SSH Brute-Force flood attacks**, where a single attacker IP generates thousands of alerts in a short time. Without AI triage, every individual alert would land on the analyst's dashboard — creating noise that buries real threats.

### Objective

> Develop a Human-AI Collaboration SOC system that reduces false alarms without compromising detection accuracy.

---

## Architecture

The system is deployed on **Azure Student Free-Tier** infrastructure and integrates three core components:

```
┌─────────────────────────────────────────────────────────────┐
│                     Azure Cloud (Student)                    │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐   ┌───────────────┐  │
│  │ Wazuh Agent  │    │ Wazuh Agent  │   │  Wazuh Agent  │  │
│  │ (raya-agent) │    │ (agent-runa) │   │  (ID: 000)    │  │
│  └──────┬───────┘    └──────┬───────┘   └───────┬───────┘  │
│         │                  │                    │           │
│         └──────────────────┴────────────────────┘           │
│                            │                                │
│                   ┌────────▼────────┐                       │
│                   │  Wazuh Manager  │                       │
│                   │  (alerts.log)   │                       │
│                   └────────┬────────┘                       │
│                            │                                │
│              ┌─────────────▼─────────────┐                  │
│              │   AI Triage Engine        │                  │
│              │   (RandomForest Model)    │                  │
│              │   parse_alerts.py         │                  │
│              └─────────────┬─────────────┘                  │
│                            │                                │
│         ┌──────────────────┼──────────────────┐             │
│         ▼                  ▼                  ▼             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │Auto-dismiss  │  │Human Review  │  │Auto-escalate to  │   │
│  │(False Alarm) │  │(Analyst)     │  │SOAR (Block IP)   │   │
│  └─────────────┘  └──────────────┘  └──────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Registered Wazuh Agents

| Agent ID | Name | IP | Status |
|----------|------|----|--------|
| 000 | Wazuh-Manager | 127.0.0.1 | Active/Local |
| 001 | raya-agent | any | Active |
| 002 | agent-runa | any | Active |

> <img width="871" height="243" alt="image" src="https://github.com/user-attachments/assets/3d07182e-7070-4901-83b2-4730dda6934f" />

---

## 🔧 Tech Stack

| Komponen | Teknologi |
|----------|-----------|
| SIEM | [Wazuh](https://wazuh.com/) |
| SOAR | *(Shuffle / TheHive / StackStorm — sesuaikan dengan yang dipakai)* |
| Cloud | Microsoft Azure (Student Free Tier) |
| AI / ML | scikit-learn (RandomForest, IsolationForest) |
| Language | Python 3 |
| Notebook | Jupyter Notebook |
| Data | CSV export dari Wazuh alert logs |

---

## AI Model — RandomForest Classifier

### Why RandomForest?

Dipilih karena:
- *Tidak memerlukan API eksternal* — berjalan sepenuhnya di server Azure sendiri (sesuai requirement project)
- Mampu menangani fitur campuran (count, rate, flag)
- Tahan terhadap overfitting melalui ensemble (200 trees)
- Menghasilkan *confidence score (probability)* yang diperlukan untuk sistem triage 3-tingkat

### Model Parameters

```python
RandomForestClassifier(
    n_estimators=200,
    max_depth=6,
    random_state=42,
    class_weight='balanced'   # menangani class imbalance
)
```

### Feature Engineering

Deteksi dilakukan bukan pada alert individual, melainkan pada *agregasi per time-window (30 detik)* per `src_ip`. Fitur yang digunakan:

| Fitur | Deskripsi |
|-------|-----------|
| `event_count` | Jumlah alert dalam window 30 detik |
| `unique_rules` | Variasi jenis rule yang terpicu |
| `unique_usernames` | Jumlah username berbeda yang dicoba (indikasi brute force) |
| `failed_pwd_count` | Jumlah percobaan password gagal |
| `invalid_user_count` | Jumlah percobaan ke user yang tidak ada |
| `bruteforce_flag_count` | Jumlah alert yang sudah ditandai Wazuh sebagai brute force |
| `max_rule_level` | Severity Wazuh tertinggi dalam window |
| `avg_rule_level` | Rata-rata severity Wazuh dalam window |
| `events_per_sec` | **Rate alert per detik** — indikator utama pola flood/DDoS |

### AI dalam Arsitektur Human-AI Loop

Model ini menempati posisi **AI Capabilities** dalam arsitektur:
- **Large Scale Data Processing** — memproses ribuan log sekaligus
- **Predictive Decision Analytics** — klasifikasi alert secara otomatis
- **Tier 1 & 2 Alerts Management** — berperan dalam Correlation, Prioritization, Triage, Validation

---

## False Alarm Criteria

Sesuai requirement *"Independently define the criteria for false alarms based on data from Wazuh"*, kriteria berikut didefinisikan dari analisis data:

### REAL ATTACK (label = 1) — jika salah satu terpenuhi:

1. `event_count >= 5` **DAN** `(invalid_user_count + failed_pwd_count) >= 5`
   → *Credential stuffing / brute force burst* nyata, bukan salah ketik manual

2. `bruteforce_flag_count > 0`
   → Wazuh sudah menandai rule brute-force (sinyal kuat)

3. `events_per_sec >= 0.5` **DAN** `unique_usernames >= 2`
   → Rate tinggi dengan banyak username = ciri khas flood/DDoS otomatis

### FALSE ALARM / NOISE (label = 0):

- Login gagal tunggal/sporadis (`event_count` kecil, rate rendah) — wajar dalam operasional normal
- Event administratif: instalasi dpkg, sesi PAM normal, sudo oleh user sah, status agent Wazuh

---

## Human-AI Collaboration Flow

Berdasarkan **AI Autonomy Levels (Level 0–4)** dan prinsip **Human-on-the-Loop (HOtL)**:

```
                      Alert Masuk dari Wazuh
                              │
                              ▼
                    ┌─────────────────┐
                    │  AI Model       │
                    │  predict_proba()│
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         proba < 0.2   0.2 ≤ p ≤ 0.8   proba > 0.8
              │              │              │
              ▼              ▼              ▼
       Auto-dismiss    Human Review    Auto-escalate
       (False Alarm)    Needed         to SOAR
       Level 2-3 AI    Level 1 HOtL   Level 3 AI
                              │              │
                              ▼              ▼
                       Analyst Review   Block IP via
                       + Feedback       Active Response
                              │
                              ▼
                       Label baru →
                       Retrain model
                       (Feedback Loop)
```
---

## Benchmark Metrics

Metrik yang digunakan untuk evaluasi:

| Metrik | Keterangan |
|--------|------------|
| **Precision** | Dari alert yang diprediksi sebagai serangan, berapa % yang benar |
| **Recall** | Dari serangan nyata, berapa % yang berhasil terdeteksi |
| **F1-Score** | Harmonic mean precision & recall |
| **ROC AUC** | Kemampuan model memisahkan kelas real attack vs false alarm |
| **Confusion Matrix** | True Positive, False Positive, True Negative, False Negative |
| **Alert Reduction Rate** | Berapa % alert yang tidak perlu disentuh manusia secara langsung |
| **False Negative Rate** | Serangan nyata yang lolos dari deteksi AI (harus mendekati 0%) |
| **Mean Time to Triage** | Waktu rata-rata triage sebelum vs sesudah AI (opsional) |

---

## 📈 Results & Analysis

### Dataset Overview

- **Total alerts diekspor dari Wazuh:** 6.621 alerts
- **Rentang waktu:** *(isi sesuai data aktual)*

### Top 10 Alert Types (dari parse_alerts.py)

| Rule Description | Count |
|-----------------|-------|
| sshd: Attempt to login using a non-existent user | 3.023 |
| PAM: User login failed | 1.738 |
| sshd: authentication failed | 490 |
| PAM: Multiple failed logins in a small period of time | 239 |
| Dpkg (Debian Package) half configured | 184 |
| New dpkg (Debian Package) installed | 184 |
| New dpkg (Debian Package) requested to install | 170 |
| PAM: Login session closed | 76 |
| PAM: Login session opened | 71 |
| Successful sudo to ROOT executed | 65 |

> <img width="845" height="410" alt="image" src="https://github.com/user-attachments/assets/c8f8e100-244c-46b6-a25f-b04aa2912acf" />


### Key Finding — Attacker Profile

IP `145.239.196.189` menyumbang **>4.900 alert (>70% dari total alert dengan `src_ip` terisi)**, seluruhnya berupa SSH brute-force burst dengan median gap antar-event **mendekati 0 detik** — pola **volumetric flood** klasik.

### DDoS Simulation Evidence

> <img width="1367" height="395" alt="image" src="https://github.com/user-attachments/assets/a80d889d-2d10-437f-925a-a42ff5de9af9" />


Alert yang muncul menunjukkan pattern `agent_flooding` dengan tag `pci_dss_10.6.1,gdpr_IV_35.7.d` — Wazuh mendeteksi agent event queue overflow akibat volume serangan yang sangat tinggi (Rule 204, level 12: *"Agent event queue is flooded"*).

### Model Performance

> <img width="254" height="84" alt="image" src="https://github.com/user-attachments/assets/a6cae853-a922-4a94-b197-b39054db5d50" />

> <img width="275" height="190" alt="image" src="https://github.com/user-attachments/assets/ec129e23-e412-41ab-9f88-00fc7ad37bb5" />

> <img width="215" height="195" alt="image" src="https://github.com/user-attachments/assets/a1ab15b8-7861-4838-b89e-4e80fb8fc372" />

> <img width="452" height="284" alt="image" src="https://github.com/user-attachments/assets/55ef3c3c-d8a7-48f6-93b0-e0a4ed15deb7" />

### Triage Distribution

> <img width="467" height="188" alt="image" src="https://github.com/user-attachments/assets/99fe8c5e-6b9d-4cf9-907d-01006c6680f1" />

| Triage Action | Jumlah |
|---------------|--------|
| Auto-dismiss (False Alarm) | *125* |
| Human Review Needed | *4* | 
| Auto-escalate to SOAR | *109* | 

### Important Note on Evaluation

Label pada dataset ini dihasilkan dari **rule heuristik berbasis fitur yang sama** (weak supervision / rule-based labeling), sehingga performa model yang terlihat sangat tinggi merupakan **proof-of-concept**, bukan bukti model sempurna di lingkungan produksi. Untuk deployment nyata:

- Gunakan feedback analis SOC (label dari investigasi nyata) untuk retrain model
- Tambahkan data log traffic-level (SYN/ICMP flood, NetFlow/Suricata) untuk generalisasi ke jenis DDoS lain
- Validasi threshold triage (0.2 / 0.8) dengan red-team simulation di lab Azure

---

## Repository Structure

```
soc-human-ai-collaboration/
│
├── notebooks/
│   └── SOC_DDoS_Triage_Notebook.ipynb    # Main AI triage notebook
│
├── scripts/
│   └── parse_alerts.py                    # Script export & parse alert Wazuh → CSV
│
├── data/
│   └── wazuh_alerts.csv                   # Dataset alert dari Wazuh (6621 rows)
│
├── model/
│   ├── soc_triage_rf_model.joblib         # Trained RandomForest model
│   └── soc_triage_features.joblib         # Feature list untuk inferensi
│
├── docs/
│   ├── architecture_diagram.png           # Diagram arsitektur sistem
│   ├── human_ai_loop.png                  # Diagram Human-AI Collaboration
│   ├── wazuh_agent_muncul.jpeg            # Screenshot agent Wazuh aktif
│   ├── dokumentasi_dapatkan_file_csv.jpeg # Screenshot parse_alerts output
│   └── dokumentasi_ddos.jpeg             # Screenshot DDoS alert logs
│
├── requirements.txt                    # Python dependencies
└── README.md                          # Dokumentasi ini
```

---

## Setup & Installation

### Prerequisites

- Python 3.8+
- Wazuh Manager (sudah terpasang di Azure VM)
- Akses ke `/var/ossec/logs/alerts/alerts.log`

### 1. Clone Repository

```bash
git clone https://github.com/<username>/soc-human-ai-collaboration.git
cd soc-human-ai-collaboration
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

**requirements.txt:**

```
pandas>=1.5.0
numpy>=1.23.0
scikit-learn>=1.2.0
matplotlib>=3.6.0
joblib>=1.2.0
jupyter>=1.0.0
```

### 3. Export Alert Data dari Wazuh

```bash
# Jalankan di Wazuh Manager (Azure VM)
python3 scripts/parse_alerts.py
# Output: wazuh_alerts.csv (6621 alerts)
```

### 4. Jalankan Notebook

```bash
jupyter notebook notebooks/SOC_DDoS_Triage_Notebook.ipynb
```

### 5. Load Model untuk Inferensi

```python
import joblib

clf = joblib.load('model/soc_triage_rf_model.joblib')
features = joblib.load('model/soc_triage_features.joblib')

# Prediksi pada window baru
proba = clf.predict_proba(X_new[features])[:, 1]
```

### 6. Monitor DDoS Alert Realtime (di Wazuh Manager)

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep -i "web\|http\|flood\|ddos"
```

---

## Documentation

- **Final Report:** `docs/Final_Project_SOC_Genap_24_25.docx`
- **AI Notebook:** `notebooks/SOC_DDoS_Triage_Notebook.ipynb`
- **Wazuh Documentation:** https://documentation.wazuh.com
- **scikit-learn RandomForest:** https://scikit-learn.org/stable/modules/ensemble.html#random-forests

---
