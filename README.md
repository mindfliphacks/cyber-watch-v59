# CyberWatch: Real-Time Threat Intelligence Monitor

CyberWatch is a Python-based Threat Intelligence dashboard that aggregates, scores, and visualizes real-time cybersecurity news from over 40+ sources (CISA, Talos, The Hacker News, Dark Reading, etc.). 

It uses a custom weighting algorithm to map keywords to **MITRE ATT&CK** tactics and assigns a "DEFCON" threat level based on the current influx of critical vulnerabilities.

## 🚀 Features

* **Aggregated Intelligence:** Pulls RSS feeds from top-tier security researchers, government agencies, and tech news.
* **Threat Scoring Engine:** Analyzes article content to assign a threat score (0-100) based on keywords (Ransomware, Zero-Day, CVE, RCE).
* **MITRE ATT&CK Mapping:** Automatically tags articles with tactics like *Initial Access*, *Privilege Escalation*, and *Exfiltration*.
* **Cyberpunk UI:** A responsive, dark-mode dashboard with a Matrix-style background, real-time clock, and news ticker.
* **Local Caching:** Implements JSON-based caching to prevent rate-limiting and improve load times.
* **Export Options:** Export intelligence reports to CSV or JSON.
* **Reader Mode:** Scrapes and cleans article content for reading directly within the dashboard.

## 🛠️ Installation

1.  **Clone the repository**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/CyberWatch.git](https://github.com/YOUR_USERNAME/CyberWatch.git)
    cd CyberWatch
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the Application**
    ```bash
    python3 cyberwatch.py
    ```

4.  **Access the Dashboard**
    Open your browser and navigate to `http://127.0.0.1:5000`

## ⚙️ How It Works

The application runs a Flask server that performs the following:
1.  **Fetch:** Asynchronously fetches RSS data from the configured feed list.
2.  **Normalize:** Cleans HTML tags and standardizes dates.
3.  **Analyze:** Scans text for IOCs (IP addresses), CVEs (e.g., CVE-2024-XXXX), and threat actors.
4.  **Visualize:** Renders a single-page application (SPA) style interface with dynamic filtering.

## 📸 Screenshots

*(You can upload a screenshot of your dashboard here later)*

## 📜 License

MIT License
