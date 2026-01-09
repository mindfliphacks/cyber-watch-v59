import feedparser
import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template_string, request, jsonify, make_response
from datetime import datetime, timedelta, timezone
import time
import re
from html import unescape
from collections import Counter
import json
import hashlib
import csv
import io
import ssl
import concurrent.futures
import os
import random
import calendar

# Fix for some RSS feeds with SSL issues
if hasattr(ssl, '_create_unverified_context'):
    ssl._create_default_https_context = ssl._create_unverified_context

app = Flask(__name__)
# Bump cache version to force fresh data structure (Crucial for ID matching)
CACHE_FILE = "cyber_monitor_cache_v13.json"

# Define IST Timezone (UTC + 5:30)
IST = timezone(timedelta(hours=5, minutes=30))

# --- CONFIGURATION ---
RSS_FEEDS = [
    # Top Tier Security & Threat Intel
    {"source": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "sec"},
    {"source": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "sec"},
    {"source": "CISA Alerts", "url": "https://www.cisa.gov/uscert/ncas/alerts.xml", "type": "gov"},
    {"source": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "type": "sec"},
    {"source": "SecurityWeek", "url": "https://feeds.feedburner.com/securityweek", "type": "sec"},
    {"source": "The Daily Swig", "url": "https://portswigger.net/daily-swig/rss", "type": "sec"},
    {"source": "Cisco Talos", "url": "http://feeds.feedburner.com/feedburner/Talos", "type": "sec"},
    {"source": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "type": "sec"},
    {"source": "Google Project Zero", "url": "http://googleprojectzero.blogspot.com/feeds/posts/default", "type": "sec"},
    {"source": "Trend Micro", "url": "https://feeds.feedburner.com/TrendMicroResearch", "type": "sec"},
    {"source": "Threatpost", "url": "https://threatpost.com/feed/", "type": "sec"},
    {"source": "Schneier on Security", "url": "https://www.schneier.com/feed/atom/", "type": "sec"},
    {"source": "Mandiant", "url": "https://www.mandiant.com/resources/blog/rss.xml", "type": "sec"},
    {"source": "CrowdStrike", "url": "https://www.crowdstrike.com/blog/feed/", "type": "sec"},
    {"source": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "sec"},
    {"source": "Check Point Research", "url": "https://research.checkpoint.com/feed/", "type": "sec"},
    {"source": "Sophos News", "url": "https://news.sophos.com/en-us/feed/", "type": "sec"},
    {"source": "WeLiveSecurity", "url": "https://www.welivesecurity.com/feed/", "type": "sec"},
    {"source": "Securelist", "url": "https://securelist.com/feed/", "type": "sec"},
    {"source": "Graham Cluley", "url": "https://grahamcluley.com/feed/", "type": "sec"},
    {"source": "Infosecurity Magazine", "url": "https://www.infosecurity-magazine.com/rss/news/", "type": "sec"},
    {"source": "IT Security Guru", "url": "https://itsecurityguru.org/feed/", "type": "sec"},
    {"source": "Microsoft Security", "url": "https://www.microsoft.com/security/blog/feed/", "type": "sec"},
    {"source": "Recorded Future", "url": "https://www.recordedfuture.com/feed", "type": "sec"},
    {"source": "SentinelOne", "url": "https://www.sentinelone.com/feed/", "type": "sec"},
    {"source": "Help Net Security", "url": "https://www.helpnetsecurity.com/feed/", "type": "sec"},
    {"source": "The Record", "url": "https://therecord.media/feed/", "type": "sec"},
    {"source": "HackRead", "url": "https://www.hackread.com/feed/", "type": "sec"},
    {"source": "Proofpoint", "url": "https://www.proofpoint.com/us/rss.xml", "type": "sec"},
    {"source": "Red Canary", "url": "https://redcanary.com/blog/feed/", "type": "sec"},
    
    # New Advanced Feeds
    {"source": "SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml", "type": "sec"},
    {"source": "Exploit-DB", "url": "https://www.exploit-db.com/rss.xml", "type": "sec"},
    {"source": "Fortinet Guard", "url": "https://www.fortinet.com/rss/threat-research.xml", "type": "sec"},
    {"source": "Packet Storm", "url": "https://www.packetstormsecurity.com/feeds/news", "type": "sec"},
    {"source": "CERT-IN", "url": "https://www.cert-in.org.in/RSS/rss.xml", "type": "gov"},

    # Tech & General
    {"source": "The Verge", "url": "https://www.theverge.com/rss/index.xml", "type": "tech"},
    {"source": "Wired", "url": "https://www.wired.com/feed/rss", "type": "tech"},
    {"source": "Ars Technica", "url": "https://feeds.arstechnica.com/arstechnica/index", "type": "tech"},
    {"source": "TechCrunch", "url": "https://techcrunch.com/feed/", "type": "tech"},
    {"source": "ZDNet", "url": "https://www.zdnet.com/news/rss.xml", "type": "tech"}
]

# Robust ID Generation (Alphanumeric only)
def generate_id(text):
    return re.sub(r'[^a-zA-Z0-9]', '', text).lower()

# Ensure IDs are assigned
for feed in RSS_FEEDS:
    feed['id'] = generate_id(feed['source'])

# MITRE ATT&CK Mapping
MITRE_TACTICS = {
    "Initial Access": ["phishing", "spearphishing", "exploit public-facing", "valid accounts", "compromised"],
    "Execution": ["command and control", "powershell", "cmd.exe", "scheduled task", "cron", "scripting"],
    "Persistence": ["backdoor", "webshell", "rootkit", "boot kit", "account manipulation", "registry"],
    "Privilege Escalation": ["sudo", "uac bypass", "exploit", "privilege", "elevation"],
    "Defense Evasion": ["obfuscated", "encrypted", "packing", "hiding", "impersonation", "masquerading"],
    "Credential Access": ["dumping", "brute force", "keylogger", "credential", "kerberoasting"],
    "Discovery": ["scanning", "reconnaissance", "network sniffing", "whoami"],
    "Lateral Movement": ["smb", "rdp", "ssh", "psexec", "remote services", "lateral"],
    "Exfiltration": ["exfiltrated", "stolen data", "leak", "upload", "transfer"],
    "Impact": ["ransomware", "encrypt", "wipe", "destroy", "denial of service", "ddos"]
}

# Advanced Categorization & Weighting
KEYWORD_WEIGHTS = {
    "zero-day": 10, "0-day": 10, "active exploitation": 10, "unpatched": 8, "rce": 9,
    "remote code execution": 9, "ransomware": 8, "breach": 6, "leak": 5, "database": 4,
    "malware": 4, "spyware": 4, "trojan": 4, "botnet": 5, "rootkit": 6,
    "critical": 5, "vulnerability": 3, "cve": 3, "patch": 2,
    "artificial intelligence": 1, "chatgpt": 1, "startup": 1
}

CATEGORY_MAPPING = {
    "Zero-Day": ["zero-day", "0-day", "active exploitation"],
    "Ransomware": ["ransomware", "encrypt", "extortion", "lockbit", "clop", "blackcat", "royal", "play ransomware", "darkside", "akira", "bastion", "lockbit3", "ransomhub"],
    "Breach": ["breach", "leak", "stolen", "database", "exposed", "dump", "hacked", "data theft"],
    "Malware": ["malware", "spyware", "trojan", "botnet", "backdoor", "rootkit", "stealer", "rat"],
    "Vulnerability": ["vulnerability", "cve", "patch", "rce", "remote code execution", "critical", "cvss"],
    "AI & Tech": ["artificial intelligence", " ai ", "chatgpt", "llm", "startup", "gadget", "apple", "google", "microsoft", "nvidia", "silicon", "cloud", "copilot"]
}

CACHE_TIMEOUT = 300  # 5 minutes
NEWS_CACHE = {
    'last_updated': 0,
    'data': [],
    'stats': {},
    'top_tags': [],
    'sources': [],
    'timeline': [],
    'top_cves': [],
    'feed_health': []
}

# --- PERSISTENCE ---
def load_cache():
    global NEWS_CACHE
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                data = json.load(f)
                if time.time() - data.get('last_updated', 0) < CACHE_TIMEOUT:
                    if data['data'] and 'source_id' in data['data'][0]:
                        NEWS_CACHE = data
                        print("Loaded valid cache from disk.")
                        return True
        except Exception as e:
            print(f"Cache load failed: {e}")
    return False

def save_cache():
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(NEWS_CACHE, f)
            print("Cache saved to disk.")
    except Exception as e:
        print(f"Cache save failed: {e}")

# --- CORE LOGIC ---

def clean_html(raw_html):
    cleanr = re.compile('<.*?>')
    cleantext = re.sub(cleanr, '', raw_html)
    return unescape(cleantext).strip()

def clean_for_attr(text):
    if not text: return ""
    return re.sub(r'[\r\n"\']+', ' ', text).strip()

def generate_gradient(text):
    hash_object = hashlib.md5(text.encode())
    hash_hex = hash_object.hexdigest()
    color1 = '#' + hash_hex[:6]
    color2 = '#' + hash_hex[6:12]
    return f"linear-gradient(135deg, {color1}, {color2})"

def get_time_ago(pub_date_ts):
    try:
        pub_date = datetime.fromtimestamp(pub_date_ts, tz=IST)
        now = datetime.now(IST)
        diff = now - pub_date
        seconds = diff.total_seconds()
        
        if seconds < 60: return "Just now"
        elif seconds < 3600: return f"{int(seconds // 60)}m ago"
        elif seconds < 86400: return f"{int(seconds // 3600)}h ago"
        elif seconds < 604800: return f"{int(seconds // 86400)}d ago"
        else: return pub_date.strftime("%b %d")
    except: return "Unknown"

def extract_image(entry):
    if 'media_content' in entry:
        for media in entry.media_content:
            if media.get('type', '').startswith('image'): return media['url']
    if 'media_thumbnail' in entry: return entry.media_thumbnail[0]['url']
    if 'links' in entry:
        for link in entry.links:
            if link.get('type', '').startswith('image'): return link['href']
    if 'summary' in entry:
        soup = BeautifulSoup(entry.summary, 'html.parser')
        img = soup.find('img')
        if img and img.get('src'): return img['src']
    return None

def link_cves(text):
    pattern = r'(CVE-\d{4}-\d{4,7})'
    return re.sub(pattern, r'<a href="https://nvd.nist.gov/vuln/detail/\1" target="_blank" style="color:var(--cyan);text-decoration:underline;font-weight:bold;">\1</a>', text, flags=re.IGNORECASE)

def extract_cves(text):
    return list(set(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)))

def extract_iocs(text):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = list(set(re.findall(ip_pattern, text)))
    filtered = [ip for ip in ips if not ip.startswith(('127.', '192.168', '10.', '0.0'))]
    return {"ips": filtered, "count": len(filtered)}

def determine_category(text):
    text = text.lower()
    for cat, keywords in CATEGORY_MAPPING.items():
        for keyword in keywords:
            if keyword in text: return cat
    return "General"

def analyze_threat_level(title, summary, feed_type):
    text_lower = (title + " " + summary).lower()
    score = 0
    detected = []
    mitre_tags = []
    
    for keyword, weight in KEYWORD_WEIGHTS.items():
        if keyword in text_lower:
            score += weight
            detected.append(keyword)
    
    for tactic, keywords in MITRE_TACTICS.items():
        if any(k in text_lower for k in keywords):
            mitre_tags.append(tactic)
            score += 2
            
    if feed_type == "tech" and score < 5: score = 0 
    
    category = determine_category(text_lower)
    if feed_type == "tech" and category == "General": category = "AI & Tech"
    
    return score, category, list(set(detected)), list(set(mitre_tags))

def scrape_article_content(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=8)
        soup = BeautifulSoup(response.content, 'html.parser')
        for s in soup(["script", "style", "nav", "footer", "aside"]): s.decompose()
        
        content = soup.find('article') or soup.find('main') or soup.find('div', class_=re.compile('content|post'))
        
        if content:
            output = ""
            h1 = soup.find('h1')
            if h1: output += f"<h1 style='color:#66fcf1;margin-bottom:20px;border-bottom:1px solid #333;padding-bottom:10px;font-family:monospace;'>{h1.get_text().strip()}</h1>"
            for tag in content.find_all(['p', 'h2', 'h3', 'ul', 'img']):
                if tag.name == 'img' and tag.get('src', '').startswith('http'):
                    output += f'<img src="{tag["src"]}" style="max-width:100%;border-radius:4px;margin:20px 0;">'
                elif tag.name in ['h2', 'h3']:
                    output += f'<{tag.name} style="color:#4fc3f7;margin-top:20px;font-family:monospace;">{tag.get_text().strip()}</{tag.name}>'
                else:
                    if len(tag.get_text()) > 30: output += f'<p style="margin-bottom:15px;line-height:1.6;font-family:monospace;">{tag.get_text().strip()}</p>'
            return output if output else "Content extraction failed (Empty)."
        return "Could not auto-detect content structure."
    except Exception as e:
        return f"Error fetching content: {str(e)}"

# --- FETCHING ---
def fetch_single_feed(feed):
    result = {'articles': [], 'status': 'error', 'source': feed['source']}
    try:
        start = time.time()
        parsed = feedparser.parse(feed['url'])
        duration = time.time() - start
        
        limit = 15 if feed['type'] == 'tech' else 25
        for entry in parsed.entries[:limit]:
            title = entry.title
            link = entry.link
            
            try:
                # Handle time parsing safely and convert to UTC
                if 'published_parsed' in entry and entry.published_parsed:
                    ts = calendar.timegm(entry.published_parsed)
                elif 'updated_parsed' in entry and entry.updated_parsed:
                    ts = calendar.timegm(entry.updated_parsed)
                else:
                    ts = time.time()
            except:
                ts = time.time()

            summary = clean_html(entry.get("summary", "") or entry.get("description", ""))
            score, category, keywords, mitre = analyze_threat_level(title, summary, feed['type'])
            
            card_color = "border-glass"
            if score >= 10: card_color = "border-red"
            elif score >= 5: card_color = "border-orange"

            result['articles'].append({
                "source": feed['source'],
                "source_id": feed['id'],
                "title": title,
                "link": link,
                "timestamp": ts, 
                "summary": link_cves(summary[:250] + "..."),
                "clean_content": clean_for_attr(title + " " + summary + " " + feed['source']), 
                "score": score,
                "category": category,
                "keywords": keywords,
                "mitre": mitre,
                "cves": extract_cves(title + " " + summary),
                "iocs": extract_iocs(title + " " + summary),
                "image": extract_image(entry),
                "gradient": generate_gradient(title),
                "class": "critical" if score >= 15 else "warning" if score >= 5 else "info",
                "card_color": card_color,
                "display_date": datetime.fromtimestamp(ts, timezone.utc).astimezone(IST).strftime("%Y-%m-%d %H:%M"),
                "relative_time": get_time_ago(ts),
                "score_percent": min(score * 5, 100),
                "confidence": min(100, 50 + (len(keywords) * 10))
            })
        result['status'] = 'ok'
        result['latency'] = round(duration, 2)
    except Exception as e:
        result['error'] = str(e)
    return result

def fetch_news(force_refresh=False):
    global NEWS_CACHE
    if not force_refresh and not NEWS_CACHE['data']:
         if load_cache(): return NEWS_CACHE
    if not force_refresh and (time.time() - NEWS_CACHE['last_updated'] < CACHE_TIMEOUT) and NEWS_CACHE['data']:
        return NEWS_CACHE

    print("Fetching fresh data...")
    articles = []
    stats = {"Critical": 0, "Vulnerability": 0, "Ransomware": 0, "Breach": 0, "Malware": 0, "AI & Tech": 0, "General": 0}
    cve_counter = Counter()
    all_keywords = []
    sources_counter = Counter()
    timeline_data = Counter()
    feed_health = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_single_feed, feed): feed for feed in RSS_FEEDS}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            feed_health.append({'source': res['source'], 'status': res['status'], 'latency': res.get('latency', 0)})
            if res['status'] == 'ok':
                for art in res['articles']:
                    articles.append(art)
                    if art['score'] >= 15: stats["Critical"] += 1
                    if art['category'] in stats: stats[art['category']] += 1
                    else: stats["General"] += 1
                    for cve in art['cves']: cve_counter[cve] += 1
                    all_keywords.extend(art['keywords'])
                    sources_counter[art['source']] += 1
                    d_key = datetime.fromtimestamp(art['timestamp']).strftime("%Y-%m-%d")
                    timeline_data[d_key] += 1

    articles.sort(key=lambda x: (x['score']*1000 + x['timestamp']), reverse=True)
    
    sorted_sources = []
    source_id_map = {feed['source']: feed['id'] for feed in RSS_FEEDS}
    for src, count in sorted(sources_counter.items()):
        src_id = source_id_map.get(src, generate_id(src))
        sorted_sources.append({'name': src, 'id': src_id, 'count': count})
    sorted_sources.sort(key=lambda x: x['count'], reverse=True)
    
    defcon = 5
    if articles:
        crit_ratio = stats["Critical"] / len(articles)
        if crit_ratio > 0.2: defcon = 1
        elif crit_ratio > 0.15: defcon = 2
        elif crit_ratio > 0.1: defcon = 3
        elif crit_ratio > 0.05: defcon = 4
    stats['defcon'] = defcon

    NEWS_CACHE = {
        'data': articles,
        'stats': stats,
        'top_tags': Counter(all_keywords).most_common(12),
        'sources': sorted_sources,
        'timeline': [{"date": k, "count": v} for k, v in sorted(timeline_data.items())[-7:]],
        'top_cves': cve_counter.most_common(5),
        'feed_health': feed_health,
        'last_updated': time.time()
    }
    save_cache()
    return NEWS_CACHE

# --- WEB INTERFACE ---

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberWatch v59.0 | Apex Overwatch</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@500;600;700;800&family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-deep: #050507;
            --bg-panel: rgba(10, 12, 16, 0.95);
            --bg-card: rgba(18, 22, 28, 0.85);
            --glass-border: rgba(102, 252, 241, 0.2);
            --text-main: #cbd5e1;
            --text-bright: #ffffff;
            --text-muted: #64748b;
            --cyan: #66fcf1;
            --blue: #3b82f6;
            --purple: #8b5cf6;
            --red: #ef4444;
            --orange: #f59e0b;
            --green: #10b981;
            --glow-cyan: 0 0 15px rgba(6, 182, 212, 0.5);
            --glow-red: 0 0 18px rgba(239, 68, 68, 0.5);
            --shadow-card: 0 15px 50px -10px rgba(0, 0, 0, 0.9);
            
            /* DEFCON Colors */
            --defcon-1: #ff0000;
            --defcon-2: #ff4500;
            --defcon-3: #ffcc00;
            --defcon-4: #00ff00;
            --defcon-5: #00bfff;
        }
        
        * { box-sizing: border-box; scrollbar-width: thin; scrollbar-color: #334155 #050507; }
        
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-deep);
            color: var(--text-main);
            margin: 0;
            display: flex;
            min-height: 100vh;
            overflow-x: hidden;
            background: #050507;
        }

        #matrixCanvas {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1;
            background: radial-gradient(circle at 50% 0%, #0f172a 0%, #020408 100%);
        }

        /* SIDEBAR */
        .sidebar {
            width: 340px; background: var(--bg-panel); border-right: 1px solid var(--glass-border); padding: 25px;
            display: flex; flex-direction: column; position: fixed; height: 100vh; z-index: 100;
            transition: transform 0.3s ease; backdrop-filter: blur(20px);
            overflow-y: auto; /* Added for scrolling */
            padding-bottom: 50px;
        }
        .sidebar::-webkit-scrollbar { width: 4px; }
        .sidebar::-webkit-scrollbar-track { background: #0f1115; }
        .sidebar::-webkit-scrollbar-thumb { background: #334155; border-radius: 2px; }
        
        .sidebar.open { transform: translateX(0); }
        
        .brand {
            font-family: 'Rajdhani', sans-serif; font-size: 2rem; font-weight: 800; margin-bottom: 25px;
            display: flex; align-items: center; gap: 12px; color: white; letter-spacing: 2px; text-transform: uppercase;
            text-shadow: var(--glow-cyan);
        }
        .brand i { color: var(--cyan); }
        
        /* DEFCON INDICATOR */
        .defcon-box {
            border: 1px solid var(--glass-border); border-radius: 4px; padding: 10px; margin-bottom: 25px;
            text-align: center; background: rgba(255,255,255,0.02); transition: all 0.5s;
        }
        .defcon-title { font-size: 0.7rem; letter-spacing: 2px; color: var(--text-muted); }
        .defcon-val { font-family: 'Rajdhani'; font-size: 2rem; font-weight: 800; margin-top: 5px; text-shadow: 0 0 15px currentColor; }
        
        .nav-section { margin-bottom: 25px; }
        .nav-title { 
            font-family: 'Rajdhani', sans-serif; font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted);
            font-weight: 700; margin-bottom: 12px; padding-left: 10px; border-left: 3px solid var(--blue); opacity: 0.9;
        }

        .nav-item {
            display: flex; align-items: center; padding: 10px 14px; color: var(--text-main); text-decoration: none;
            border-radius: 4px; margin-bottom: 4px; transition: all 0.2s ease; cursor: pointer; font-size: 0.9rem;
            font-weight: 500; border: 1px solid transparent; position: relative; overflow: hidden;
        }
        .nav-item:hover { background: rgba(255, 255, 255, 0.05); color: white; transform: translateX(5px); box-shadow: 0 0 10px rgba(6, 182, 212, 0.1); }
        .nav-item.active { 
            background: linear-gradient(90deg, rgba(6, 182, 212, 0.15), transparent); 
            color: var(--cyan); border-left: 3px solid var(--cyan); 
            box-shadow: 0 0 20px rgba(6, 182, 212, 0.15);
        }
        .nav-item i { width: 24px; text-align: center; margin-right: 12px; color: var(--text-muted); transition: color 0.2s; }
        .nav-item.active i, .nav-item:hover i { color: var(--cyan); }
        .item-count { font-size: 0.7rem; color: var(--text-muted); background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px; margin-left: auto; }

        .cve-item { font-family: 'JetBrains Mono'; font-size: 0.75rem; color: var(--red); padding: 5px 0; border-bottom: 1px solid rgba(255,255,255,0.05); cursor:pointer; }
        .cve-item:hover { color: #fff; }
        
        .chart-container {
            margin-top: auto; background: rgba(0,0,0,0.2); border-radius: 8px; padding: 15px;
            border: 1px solid var(--glass-border); position: relative; margin-bottom: 10px;
        }

        /* MAIN */
        .main-content { margin-left: 340px; flex: 1; padding-top: 40px; width: calc(100% - 340px); transition: margin 0.3s ease; }
        .main-content.focus { margin-left: 0; width: 100%; }

        /* TICKER */
        .news-ticker {
            position: fixed; top: 0; left: 340px; right: 0; height: 36px; background: rgba(8, 9, 11, 0.95);
            display: flex; align-items: center; overflow: hidden; z-index: 95; border-bottom: 1px solid var(--glass-border);
            font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; backdrop-filter: blur(5px);
        }
        .ticker-label {
            background: rgba(239, 68, 68, 0.15); color: var(--red); padding: 0 25px; height: 100%;
            display: flex; align-items: center; font-weight: 700; z-index: 2; border-right: 1px solid var(--glass-border);
        }
        .ticker-content { display: flex; animation: ticker 60s linear infinite; white-space: nowrap; }
        .ticker-item { margin-right: 60px; color: var(--text-muted); display: flex; align-items: center; cursor: pointer; transition: color 0.2s; }
        .ticker-item:hover { color: var(--text-bright); text-shadow: 0 0 5px var(--cyan); }
        .ticker-item span { color: var(--cyan); margin-right: 10px; }
        @keyframes ticker { 0% { transform: translateX(0); } 100% { transform: translateX(-100%); } }

        /* HEADER */
        header {
            background: rgba(5, 5, 7, 0.85); backdrop-filter: blur(20px); padding: 20px 40px; position: sticky;
            top: 36px; z-index: 90; border-bottom: 1px solid var(--glass-border); display: flex;
            justify-content: space-between; align-items: center; box-shadow: 0 5px 30px rgba(0, 0, 0, 0.4);
        }
        .search-input {
            background: rgba(255, 255, 255, 0.05); border: 1px solid var(--glass-border); border-radius: 4px;
            padding: 12px 15px 12px 45px; width: 450px; color: var(--text-bright); outline: none; transition: all 0.2s;
            font-family: 'Inter'; font-size: 0.95rem;
        }
        .search-input:focus { border-color: var(--blue); background: rgba(255, 255, 255, 0.09); box-shadow: var(--glow-cyan); }
        .search-container i { position: absolute; left: 16px; top: 50%; transform: translateY(-50%); color: var(--text-muted); }

        .action-group { display: flex; gap: 12px; align-items: center; }
        .action-btn {
            background: rgba(255, 255, 255, 0.03); border: 1px solid var(--glass-border); color: var(--text-main);
            padding: 10px 18px; border-radius: 4px; cursor: pointer; font-size: 0.9rem; display: flex;
            align-items: center; gap: 8px; text-decoration: none; transition: all 0.2s; font-weight: 600;
        }
        .action-btn:hover { border-color: var(--text-muted); background: rgba(255, 255, 255, 0.08); color: white; transform: translateY(-2px); }
        .action-btn.primary { background: rgba(6, 182, 212, 0.1); border-color: rgba(6, 182, 212, 0.4); color: var(--cyan); }
        .action-btn.primary:hover { background: var(--cyan); color: #050507; box-shadow: var(--glow-cyan); }
        .sort-select { background: rgba(255,255,255,0.03); border: 1px solid var(--glass-border); color: var(--text-main); padding: 10px; border-radius: 4px; font-family: 'Inter'; outline: none; }
        .sort-select option { background: #0f1115; }
        .active-filter-label { color: var(--text-muted); font-size: 0.8rem; font-family: 'JetBrains Mono'; margin-right: 15px; }

        /* CONTENT */
        .content-area { padding: 40px; }
        
        .stats-row {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 25px;
            margin-bottom: 40px; animation: fadeIn 0.6s ease-out;
        }
        .stat-card {
            background: rgba(20, 23, 30, 0.7); border: 1px solid var(--glass-border); border-radius: 8px;
            padding: 20px; display: flex; flex-direction: column; position: relative; overflow: hidden;
            backdrop-filter: blur(10px); transition: transform 0.2s;
        }
        .stat-card:hover { transform: translateY(-3px); border-color: var(--cyan); box-shadow: var(--glow-cyan); }
        .stat-val { font-family: 'Rajdhani'; font-size: 2.5rem; font-weight: 700; color: white; text-shadow: 0 0 15px rgba(255,255,255,0.1); }
        .stat-label { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1.5px; margin-top: 5px; }

        /* HERO */
        .hero-section { margin-bottom: 50px; animation: fadeIn 0.8s ease-out; }
        .hero-card {
            background: linear-gradient(110deg, rgba(15, 17, 21, 0.95) 0%, rgba(5, 5, 7, 0.9) 100%); 
            border-radius: 12px; padding: 0; border: 1px solid var(--glass-border); 
            position: relative; overflow: hidden; box-shadow: 0 25px 60px rgba(0,0,0,0.5);
            display: flex; min-height: 420px;
        }
        .hero-content { 
            flex: 1.3; padding: 60px; z-index: 2; position: relative; 
            background: linear-gradient(90deg, rgba(5, 5, 7, 1) 0%, rgba(5, 5, 7, 0.7) 100%);
            border-right: 1px solid var(--glass-border);
        }
        .hero-visual {
            flex: 0.7; background-image: url('https://images.unsplash.com/photo-1550751827-4bd374c3f58b?q=80&w=2670&auto=format&fit=crop');
            background-size: cover; background-position: center; position: relative; 
            filter: grayscale(40%) sepia(20%) hue-rotate(180deg) brightness(0.6) contrast(1.2);
        }
        .hero-visual::after { content: ''; position: absolute; inset: 0; background: linear-gradient(90deg, #050507 0%, transparent 100%); }
        .hero-badge { 
            background: rgba(239, 68, 68, 0.15); color: var(--red); padding: 8px 16px; border-radius: 4px; font-size: 0.8rem;
            font-weight: 700; display: inline-flex; align-items: center; gap: 10px; margin-bottom: 25px; letter-spacing: 2px;
            border: 1px solid rgba(239, 68, 68, 0.4); box-shadow: var(--glow-red); text-transform: uppercase;
        }
        .hero-card h1 { 
            margin: 0 0 25px 0; font-family: 'Rajdhani', sans-serif; font-size: 3.5rem; line-height: 1.1; max-width: 95%;
            letter-spacing: -0.5px; font-weight: 800; color: white; text-shadow: 0 4px 20px rgba(0,0,0,0.6);
            min-height: 120px;
        }
        .hero-card p { color: #a0a0a0; font-size: 1.25rem; max-width: 90%; margin-bottom: 40px; line-height: 1.7; font-family: 'Inter'; }

        /* GRID */
        .news-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 30px; animation: fadeInUp 0.8s ease-out; }
        .card {
            background: rgba(22, 25, 32, 0.7); backdrop-filter: blur(15px); border: 1px solid var(--glass-border); 
            border-radius: 8px; overflow: hidden; transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); 
            display: flex; flex-direction: column; height: 100%; position: relative;
            opacity: 0; animation: staggerFade 0.5s forwards;
        }
        .card:hover { transform: translateY(-8px); box-shadow: var(--shadow-card); background: rgba(30, 34, 42, 0.95); }
        
        .card.border-red { border-top: 3px solid var(--red); box-shadow: 0 -5px 20px -5px rgba(239, 68, 68, 0.2); }
        .card.border-orange { border-top: 3px solid var(--orange); }
        .card.border-glass { border-top: 1px solid var(--glass-border); }

        .card-img { height: 200px; background: #08090b; position: relative; overflow: hidden; border-bottom: 1px solid var(--glass-border); }
        .card-img img { width: 100%; height: 100%; object-fit: cover; transition: transform 0.6s; opacity: 0.8; filter: contrast(1.1); }
        .card:hover .card-img img { transform: scale(1.08); opacity: 1; filter: contrast(1.2); }
        
        .card-body { padding: 25px; flex: 1; display: flex; flex-direction: column; }
        .badge { font-size: 0.65rem; padding: 4px 10px; border-radius: 2px; font-weight: 700; background: rgba(255,255,255,0.05); color: var(--text-muted); border: 1px solid var(--glass-border); text-transform: uppercase; margin-right: 6px; font-family: 'JetBrains Mono'; }
        .badge.critical { color: var(--red); border-color: var(--red); background: rgba(239, 68, 68, 0.1); animation: pulseRed 2s infinite; }
        .badge.ioc { color: #fff; border-color: var(--orange); background: rgba(245, 158, 11, 0.2); box-shadow: 0 0 10px rgba(245, 158, 11, 0.2); }
        .badge.mitre { color: var(--purple); border-color: var(--purple); background: rgba(139, 92, 246, 0.1); }
        
        @keyframes pulseRed { 0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); } 70% { box-shadow: 0 0 0 6px rgba(239, 68, 68, 0); } 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); } }

        .card h3 { margin: 15px 0; font-family: 'Rajdhani', sans-serif; font-size: 1.5rem; line-height: 1.3; font-weight: 700; letter-spacing: 0.5px; }
        .card h3 a { color: #f1f5f9; text-decoration: none; transition: color 0.2s; }
        .card h3 a:hover { color: var(--cyan); text-shadow: 0 0 10px rgba(6, 182, 212, 0.4); }
        
        .summary { color: #94a3b8; font-size: 0.95rem; line-height: 1.6; margin-bottom: 20px; flex: 1; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }
        
        .card-footer { margin-top: auto; border-top: 1px solid var(--glass-border); padding-top: 20px; display: flex; justify-content: space-between; align-items: center; }
        .source-tag { color: var(--blue); font-weight: 700; font-size: 0.85rem; display: flex; align-items: center; gap: 6px; }
        .date-tag { font-family: 'JetBrains Mono'; font-size: 0.75rem; color: #64748b; }
        
        /* CONFIDENCE METER */
        .confidence-box { display: flex; align-items: center; gap: 5px; margin-top: 10px; font-size: 0.7rem; color: #64748b; font-family: 'JetBrains Mono'; }
        .confidence-bar { width: 50px; height: 4px; background: #333; border-radius: 2px; overflow: hidden; }
        .confidence-fill { height: 100%; background: var(--green); }

        .btn-icon {
            background: transparent; border: 1px solid var(--glass-border); color: var(--text-muted); width: 32px; height: 32px;
            border-radius: 6px; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: all 0.2s;
        }
        .btn-icon:hover { background: rgba(6, 182, 212, 0.1); color: var(--cyan); border-color: var(--cyan); box-shadow: 0 0 10px rgba(6, 182, 212, 0.2); transform: translateY(-2px); }

        .modal { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.95); z-index: 200; display: none; justify-content: center; align-items: center; padding: 40px; }
        .modal-content { background: #0b0c10; width: 950px; max-width: 100%; height: 90vh; border-radius: 4px; border: 1px solid var(--green); display: flex; flex-direction: column; animation: zoomIn 0.2s ease; font-family: 'JetBrains Mono'; box-shadow: 0 0 100px rgba(16, 185, 129, 0.1); }
        .modal-header { padding: 25px 40px; border-bottom: 1px solid var(--green); display: flex; justify-content: space-between; align-items: center; background: rgba(16, 185, 129, 0.05); }
        .modal-body { padding: 50px; overflow-y: auto; color: #00ff00; line-height: 1.7; font-size: 1rem; }
        .modal-body a { color: var(--cyan); text-decoration: underline; }
        
        .sidebar-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.8); z-index: 99; backdrop-filter: blur(5px); }
        .sidebar-overlay.active { display: block; }
        .menu-toggle { display: none; background: none; border: none; color: white; font-size: 1.5rem; }

        .source-list { max-height: 300px; overflow-y: auto; }
        .source-list::-webkit-scrollbar { width: 4px; }
        .source-list::-webkit-scrollbar-thumb { background: #334155; }
        
        /* Utility */
        .clock-display { font-family: 'JetBrains Mono'; color: var(--cyan); font-weight: bold; margin-right: 15px; border-right: 1px solid var(--glass-border); padding-right: 15px; }
        .active-filter-label { color: var(--text-muted); font-size: 0.8rem; font-family: 'JetBrains Mono'; margin-right: 15px; }

        @media (max-width: 768px) {
            .sidebar { transform: translateX(-100%); } .sidebar.open { transform: translateX(0); }
            .main-content { margin-left: 0; width: 100%; } .news-ticker { left: 0; }
            .menu-toggle { display: block; margin-right: 15px; } .hero-card { flex-direction: column; padding: 30px; }
            .stats-row { grid-template-columns: 1fr; }
        }
        
        .no-results {
            display: none; width: 100%; text-align: center; padding: 50px; color: var(--text-muted);
            font-family: 'JetBrains Mono'; letter-spacing: 1px; grid-column: 1 / -1;
        }
        
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes staggerFade { to { opacity: 1; } }
        .news-grid .card:nth-child(1) { animation-delay: 0.05s; }
        .news-grid .card:nth-child(2) { animation-delay: 0.1s; }
        .news-grid .card:nth-child(3) { animation-delay: 0.15s; }
        .news-grid .card:nth-child(4) { animation-delay: 0.2s; }
        .news-grid .card:nth-child(5) { animation-delay: 0.25s; }
    </style>
</head>
<body>

<canvas id="matrixCanvas"></canvas>

<div class="sidebar-overlay" onclick="toggleSidebar()"></div>

<div class="sidebar" id="sidebar">
    <div class="brand"><i class="fas fa-network-wired"></i> CyberWatch <span style="font-size:0.7rem; color:var(--cyan); margin-left:8px; border:1px solid var(--cyan); padding:2px 6px; border-radius:2px; opacity:0.8;">v59.0</span></div>
    
    <div class="defcon-box">
        <div class="defcon-title">DEFCON LEVEL</div>
        <div class="defcon-val" id="defconDisplay" style="color:var(--defcon-{{ cache.stats.defcon }})">{{ cache.stats.defcon }}</div>
    </div>
    
    <div class="nav-section">
        <button class="action-btn" onclick="resetFilters()" style="width:100%; justify-content:center; border-color:var(--red); color:var(--red);"><i class="fas fa-undo"></i> RESET FILTERS</button>
    </div>
    
    <div id="nav-threats" class="nav-section">
        <div class="nav-title">Threat Intel</div>
        <div class="nav-item active" onclick="filterCategory('all', this)"><i class="fas fa-globe"></i> Global Feed</div>
        <div class="nav-item" onclick="filterCategory('critical', this)"><i class="fas fa-biohazard" style="color:var(--red)"></i> Critical Threats</div>
        <div class="nav-item" onclick="filterCategory('Vulnerability', this)"><i class="fas fa-fingerprint"></i> Vulnerabilities</div>
        <div class="nav-item" onclick="filterCategory('Ransomware', this)"><i class="fas fa-lock"></i> Ransomware</div>
    </div>
    
    <div id="nav-time" class="nav-section">
        <div class="nav-title">Timeframe</div>
        <div class="nav-item active" onclick="filterTime('all', this)"><i class="fas fa-infinity"></i> All Time</div>
        <div class="nav-item" onclick="filterTime(24, this)"><i class="fas fa-bolt" style="color:var(--green)"></i> Last 24 Hours</div>
        <div class="nav-item" onclick="filterTime(72, this)"><i class="fas fa-history"></i> Last 3 Days</div>
        <div class="nav-item" onclick="filterTime(168, this)"><i class="fas fa-calendar-week"></i> Last Week</div>
    </div>

    <div id="nav-sectors" class="nav-section">
        <div class="nav-title">Sectors</div>
        <div class="nav-item" onclick="filterCategory('AI & Tech', this)"><i class="fas fa-microchip"></i> Tech & AI</div>
        <div class="nav-item" onclick="filterCategory('Breach', this)"><i class="fas fa-database"></i> Data Breaches</div>
    </div>
    
    <div class="nav-section">
        <div class="nav-title">Active CVEs</div>
        {% for cve, count in cache.top_cves %}
             <div class="cve-item" onclick="document.getElementById('searchInput').value='{{ cve }}'; applyFilters()"><i class="fas fa-bug"></i> {{ cve }} ({{ count }})</div>
        {% endfor %}
    </div>
    
    <div id="nav-sources" class="nav-section">
        <div class="nav-title">Sources</div>
        <div class="source-list">
            <div class="nav-item active" onclick="filterPlatform('all', this, 'All Sources')"><i class="fas fa-rss"></i> All Sources</div>
            {% for entry in sources %}
            <div class="nav-item" onclick="filterPlatform('{{ entry.id }}', this, '{{ entry.name }}')">
                <i class="fas fa-rss" style="font-size:0.8em; opacity:0.7;"></i> {{ entry.name }} 
                <span class="item-count">{{ entry.count }}</span>
            </div>
            {% endfor %}
        </div>
    </div>

    <div class="chart-container">
        <div class="nav-title" style="margin-bottom:10px; border:none; color:white;">Threat Profile</div>
        <canvas id="categoryChart" width="220" height="200"></canvas>
    </div>
</div>

<div class="news-ticker">
    <div class="ticker-label"><i class="fas fa-satellite-dish" style="margin-right:10px;"></i> INTEL STREAM</div>
    <div class="ticker-content">
        {% for article in articles[:15] %}
        <div class="ticker-item" onclick="event.stopPropagation(); openReader(this.dataset.url, this.dataset.title)" data-url="{{ article.link|e }}" data-title="{{ article.title|e }}">
            <span>{{ article.display_date.split(' ')[1] }}</span> {{ article.title }}
        </div>
        {% endfor %}
    </div>
</div>

<div class="main-content" id="mainContent">
    <header>
        <div class="header-left">
            <button class="menu-toggle" onclick="toggleSidebar()"><i class="fas fa-bars"></i></button>
            <div class="search-container">
                <i class="fas fa-search"></i>
                <input type="text" id="searchInput" class="search-input" placeholder="Search CVEs, IPs, Actors...">
            </div>
        </div>
        
        <div class="action-group">
            <span class="active-filter-label" id="filterStatus">Global Feed</span>
            <select class="sort-select" onchange="sortArticles(this.value)">
                <option value="newest">Newest First</option>
                <option value="score">Highest Threat</option>
            </select>
            <div class="clock-display" id="liveClock"></div>
            <button class="action-btn" onclick="toggleFocus()" title="Focus Mode"><i class="fas fa-expand"></i></button>
            <a href="/export-csv" class="action-btn" title="Export CSV"><i class="fas fa-file-csv"></i></a>
            <a href="/?refresh=true" class="action-btn primary" title="Force Refresh" onclick="this.querySelector('i').classList.add('spin')"><i class="fas fa-sync-alt"></i></a>
        </div>
    </header>

    <div class="content-area">
        <!-- STATS ROW -->
        <div class="stats-row">
            <div class="stat-card">
                <div class="stat-val" style="color:var(--red)">{{ stats.Critical }}</div>
                <div class="stat-label">Critical Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-val" style="color:var(--cyan)">{{ stats.total_cves }}</div>
                <div class="stat-label">Identified CVEs</div>
            </div>
            <div class="stat-card">
                <div class="stat-val" style="color:var(--orange)">{{ stats.Ransomware }}</div>
                <div class="stat-label">Ransomware Incidents</div>
            </div>
            <div class="stat-card">
                <div class="stat-val" style="color:var(--green)">{{ sources|length }}</div>
                <div class="stat-label">Active Feeds</div>
            </div>
        </div>

        {% if cache.data and cache.data[0].score >= 5 %}
        <div class="hero-section">
            <div class="hero-card">
                <div class="hero-content">
                    <div class="hero-badge"><i class="fas fa-skull-crossbones"></i> CRITICAL THREAT DETECTED</div>
                    <h1><a href="{{ cache.data[0].link }}" target="_blank" style="text-decoration:none; color:inherit;">{{ cache.data[0].title }}</a></h1>
                    <p>{{ cache.data[0].summary }}</p>
                    <button class="action-btn primary" style="display:inline-flex; padding:14px 28px; font-size:1rem;" onclick="openReader(this)" data-url="{{ cache.data[0].link|e }}" data-title="{{ cache.data[0].title|e }}">
                        <i class="fas fa-terminal"></i> &nbsp;ANALYZE INTELLIGENCE
                    </button>
                    <div class="hero-meta">
                        <span><i class="far fa-clock" style="color:var(--green)"></i> {{ cache.data[0].relative_time }}</span>
                        <span><i class="fas fa-broadcast-tower" style="color:var(--blue)"></i> {{ cache.data[0].source }}</span>
                    </div>
                </div>
                <div class="hero-visual"></div>
            </div>
        </div>
        {% endif %}

        <div class="news-grid" id="grid">
            {% for article in cache.data %}
            <div class="card {{ article.card_color }}" 
                 data-category="{{ article.category }}" 
                 data-severity="{{ article.class }}"
                 data-timestamp="{{ article.timestamp }}"
                 data-source-id="{{ article.source_id }}"
                 data-score="{{ article.score }}"
                 data-content="{{ article.clean_content }}">
                
                <div class="card-img">
                     {% if article.image %}
                        <img src="{{ article.image }}" loading="lazy" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'">
                        <div class="placeholder-art" style="display:none; background: {{ article.gradient }}"></div>
                    {% else %}
                        <div class="placeholder-art" style="background: {{ article.gradient }}"></div>
                    {% endif %}
                </div>
                
                <div class="card-body">
                    <div class="card-tags">
                        <span class="badge {{ 'critical' if article.class == 'critical' else 'tech' }}">{{ article.category }}</span>
                        {% for tactic in article.mitre[:2] %}
                            <span class="badge mitre">{{ tactic }}</span>
                        {% endfor %}
                        {% if article.iocs.count > 0 %}
                             <span class="badge ioc" onclick="copyText('{{ article.iocs.ips|join(', ') }}')">IOC FOUND</span>
                        {% endif %}
                    </div>
                    <h3><a href="{{ article.link }}" target="_blank">{{ article.title }}</a></h3>
                    <div class="summary">{{ article.summary|safe }}</div>
                    
                    <div class="confidence-box">
                         <span>AI Confidence:</span>
                         <div class="confidence-bar">
                              <div class="confidence-fill" style="width:{{ article.confidence }}%"></div>
                         </div>
                         <span>{{ article.confidence }}%</span>
                    </div>

                    <div class="card-footer">
                        <div class="meta-col">
                            <span class="source-tag"><i class="fas fa-rss"></i> {{ article.source }}</span>
                            <span class="date-tag">{{ article.display_date }} ({{ article.relative_time }})</span>
                        </div>
                        <button class="btn-icon" title="Read Mode" onclick="openReader(this)" data-url="{{ article.link|e }}" data-title="{{ article.title|e }}">
                            <i class="fas fa-terminal"></i>
                        </button>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
        <div class="no-results" id="noResults">
             <i class="fas fa-search" style="font-size:3rem; margin-bottom:20px; opacity:0.5;"></i><br>
             NO INTEL FOUND FOR CURRENT FILTERS
             <br><br>
             <button class="action-btn" onclick="showAllFromSource()">SHOW ALL FROM THIS SOURCE</button>
             <button class="action-btn" onclick="resetFilters()" style="margin-left:10px;">RESET FILTERS</button>
        </div>
    </div>
</div>

<!-- READER MODAL -->
<div class="modal" id="readerModal">
    <div class="modal-content">
        <div class="modal-header">
            <h3 id="readerTitle" style="color:var(--green);font-family:'Rajdhani';"></h3>
            <button onclick="closeModal()" class="btn-icon" style="color:var(--red);"><i class="fas fa-times"></i></button>
        </div>
        <div class="modal-body" id="readerContent"></div>
    </div>
</div>

<!-- STATUS MODAL -->
<div class="modal" id="statusModal" style="z-index:3000;">
    <div class="modal-content" style="height:auto;max-height:80vh;">
        <div class="modal-header">
             <h3>FEED STATUS REPORT</h3>
             <button onclick="document.getElementById('statusModal').style.display='none'" class="btn-icon"><i class="fas fa-times"></i></button>
        </div>
        <div class="modal-body">
            <table style="width:100%; text-align:left; border-collapse:collapse; color:#cbd5e1;">
                <tr><th style="padding:10px;border-bottom:1px solid #333;">Source</th><th style="padding:10px;border-bottom:1px solid #333;">Status</th><th style="padding:10px;border-bottom:1px solid #333;">Latency</th></tr>
                {% for feed in cache.feed_health %}
                <tr>
                    <td style="padding:10px;border-bottom:1px solid #222;">{{ feed.source }}</td>
                    <td style="padding:10px;border-bottom:1px solid #222;color:{{ 'var(--green)' if feed.status == 'ok' else 'var(--red)' }}">{{ feed.status }}</td>
                    <td style="padding:10px;border-bottom:1px solid #222;">{{ feed.latency }}s</td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </div>
</div>

<script>
    // --- BACKGROUND ---
    const canvas = document.getElementById('matrixCanvas');
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth; canvas.height = window.innerHeight;
    let particles = [];
    class Particle {
        constructor(){ this.x = Math.random()*canvas.width; this.y = Math.random()*canvas.height; this.vx = (Math.random()-0.5)*0.5; this.vy = (Math.random()-0.5)*0.5; }
        update(){ this.x+=this.vx; this.y+=this.vy; if(this.x<0||this.x>canvas.width) this.vx*=-1; if(this.y<0||this.y>canvas.height) this.vy*=-1; }
        draw(){ ctx.fillStyle='rgba(6,182,212,0.4)'; ctx.beginPath(); ctx.arc(this.x,this.y,1,0,Math.PI*2); ctx.fill(); }
    }
    for(let i=0;i<80;i++) particles.push(new Particle());
    function animate(){ 
        ctx.clearRect(0,0,canvas.width,canvas.height);
        particles.forEach(p=>{ p.update(); p.draw(); });
        requestAnimationFrame(animate); 
    }
    animate();

    function updateClock() {
        const now = new Date();
        const options = { timeZone: 'Asia/Kolkata', hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' };
        document.getElementById('liveClock').innerText = now.toLocaleTimeString('en-US', options) + " IST";
    }
    setInterval(updateClock, 1000);
    updateClock();
    
    // --- CHART ---
    try {
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        new Chart(categoryCtx, {
            type: 'radar',
            data: {
                labels: ['Critical', 'Ransom', 'Vulns', 'Tech', 'General'],
                datasets: [{
                    label: 'Threat Profile',
                    data: [{{ stats.Critical }}, {{ stats.Ransomware }}, {{ stats.Vulnerability }}, {{ stats['AI & Tech'] }}, {{ stats.General }}],
                    backgroundColor: 'rgba(6, 182, 212, 0.2)',
                    borderColor: '#66fcf1',
                    pointBackgroundColor: '#fff',
                    pointBorderColor: '#fff'
                }]
            },
            options: {
                plugins: { legend: { display: false } },
                scales: {
                    r: {
                        angleLines: { color: 'rgba(255, 255, 255, 0.1)' },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' },
                        pointLabels: { color: '#cbd5e1', font: { family: 'Rajdhani', size: 12 } },
                        ticks: { backdropColor: 'transparent', color: 'transparent' }
                    }
                },
                responsive: true
            }
        });
    } catch(e) { console.log("Chart Init Error:", e); }

    // --- LOGIC ---
    let currentCategory = 'all';
    let currentTimeFilter = 'all'; 
    let currentPlatform = 'all';

    function toggleSidebar() { document.getElementById('sidebar').classList.toggle('open'); document.querySelector('.sidebar-overlay').classList.toggle('active'); }

    function resetFilters() {
        currentCategory = 'all'; currentTimeFilter = 'all'; currentPlatform = 'all';
        document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
        document.querySelector('#nav-threats .nav-item').classList.add('active'); // Global
        document.querySelector('#nav-time .nav-item').classList.add('active'); // All Time
        document.querySelector('#nav-sources .source-list .nav-item').classList.add('active'); // All Sources
        document.getElementById('filterStatus').innerText = 'Global Feed';
        document.getElementById('searchInput').value = '';
        applyFilters();
    }

    // Stackable Filter Logic: Don't auto-reset when picking category/source, 
    // BUT reset the OTHER if results are 0? No, let user decide.
    // However, to fix "blank screen" complaints, we should implement a "Smart Reset"
    // If I pick a Source, I probably want to see ALL categories from that Source initially.
    
    function filterCategory(type, btn) {
        document.querySelectorAll('#nav-threats .nav-item, #nav-sectors .nav-item').forEach(el => el.classList.remove('active'));
        btn.classList.add('active');
        currentCategory = type;
        
        // Smart Reset: If we pick a category, reset Source to All to avoid empty intersection
        currentPlatform = 'all';
        document.querySelectorAll('#nav-sources .nav-item').forEach(el => el.classList.remove('active'));
        document.querySelector('#nav-sources .source-list .nav-item').classList.add('active');
        
        document.getElementById('filterStatus').innerText = 'Filter: ' + type;
        applyFilters();
    }

    function filterTime(hours, btn) {
        document.querySelectorAll('#nav-time .nav-item').forEach(el => el.classList.remove('active'));
        btn.classList.add('active');
        currentTimeFilter = hours;
        applyFilters();
    }

    function filterPlatform(id, btn, name) {
        document.querySelectorAll('#nav-sources .nav-item').forEach(el => el.classList.remove('active'));
        btn.classList.add('active');
        currentPlatform = id;
        
        // Smart Reset: If we pick a source, reset Category to Global
        currentCategory = 'all';
        document.querySelectorAll('#nav-threats .nav-item, #nav-sectors .nav-item').forEach(el => el.classList.remove('active'));
        document.querySelector('#nav-threats .nav-item').classList.add('active');
        
        document.getElementById('filterStatus').innerText = 'Source: ' + name;
        applyFilters();
    }
    
    function showAllFromSource() {
         // Reset category to all, keep current platform
         currentCategory = 'all';
         document.querySelectorAll('#nav-threats .nav-item, #nav-sectors .nav-item').forEach(el => el.classList.remove('active'));
         document.querySelector('#nav-threats .nav-item').classList.add('active');
         applyFilters();
    }
    
    function sortArticles(criteria) {
        const grid = document.getElementById('grid');
        const cards = Array.from(grid.children);
        
        cards.sort((a, b) => {
            if (criteria === 'score') {
                return b.getAttribute('data-score') - a.getAttribute('data-score');
            } else {
                return b.getAttribute('data-timestamp') - a.getAttribute('data-timestamp');
            }
        });
        
        cards.forEach(card => grid.appendChild(card));
    }

    function applyFilters() {
        const cards = document.querySelectorAll('.card');
        const now = Date.now() / 1000;
        const searchTerm = document.getElementById('searchInput').value.toLowerCase();
        let count = 0;

        cards.forEach(card => {
            const cat = card.getAttribute('data-category');
            const sev = card.getAttribute('data-severity');
            const srcId = card.getAttribute('data-source-id');
            const tsStr = card.getAttribute('data-timestamp');
            const content = (card.getAttribute('data-content') || '').toLowerCase();
            
            if(!cat || !tsStr) return; 
            const ts = parseFloat(tsStr);

            let catMatch = (currentCategory === 'all') || 
                           (currentCategory === 'critical' && sev === 'critical') ||
                           (cat === currentCategory);

            let timeMatch = true;
            if(currentTimeFilter !== 'all') {
                timeMatch = (now - ts) <= (currentTimeFilter * 3600);
            }

            let srcMatch = (currentPlatform === 'all') || (srcId === currentPlatform);
            let searchMatch = !searchTerm || content.includes(searchTerm);

            if (catMatch && timeMatch && srcMatch && searchMatch) {
                card.style.display = 'flex';
                count++;
            } else {
                card.style.display = 'none';
            }
        });
        
        document.getElementById('noResults').style.display = count === 0 ? 'block' : 'none';
    }

    document.getElementById('searchInput').addEventListener('input', applyFilters);

    function openReader(btn) {
        const url = btn.getAttribute('data-url');
        const title = btn.getAttribute('data-title');
        const modal = document.getElementById('readerModal');
        const content = document.getElementById('readerContent');
        const titleEl = document.getElementById('readerTitle');
        
        modal.style.display = 'flex';
        titleEl.innerText = title;
        content.innerHTML = '<div style="text-align:center;padding-top:50px;color:var(--cyan);">LOADING INTEL...</div>';
        
        fetch(`/read-content?url=${encodeURIComponent(url)}`)
            .then(r => r.json())
            .then(data => { content.innerHTML = data.content; })
            .catch(() => { content.innerHTML = '<p style="color:var(--red);text-align:center">Connection Failed. Source blocked scraper.</p>'; });
    }

    function closeModal() { document.getElementById('readerModal').style.display = 'none'; }
    function copyText(text) { navigator.clipboard.writeText(text); alert("IOC Copied: " + text); }
    function toggleFocus() {
        const sidebar = document.getElementById('sidebar');
        const main = document.getElementById('mainContent');
        if(sidebar.style.transform === 'translateX(-100%)'){
            sidebar.style.transform = 'translateX(0)'; main.style.marginLeft = '320px';
        } else {
            sidebar.style.transform = 'translateX(-100%)'; main.style.marginLeft = '0';
        }
    }
</script>
</body>
</html>
"""

# --- ROUTES ---
@app.route('/')
def dashboard():
    force_refresh = request.args.get('refresh') == 'true'
    try:
        data = fetch_news(force_refresh=force_refresh)
        
        # Safe Unpacking
        articles = data.get('data', [])
        stats = data.get('stats', {})
        top_tags = data.get('top_tags', [])
        sources = data.get('sources', [])
        timeline = data.get('timeline', [])
        top_cves = data.get('top_cves', [])
        last_updated = datetime.fromtimestamp(data.get('last_updated', time.time()))
        last_updated_str = last_updated.strftime("%H:%M:%S")
        
        return render_template_string(HTML_TEMPLATE, cache=data, articles=articles, stats=stats, top_tags=top_tags, sources=sources, timeline=timeline, top_cves=top_cves, last_updated=last_updated_str)
    except Exception as e:
        return f"System Error: {str(e)} - Try refreshing.", 500

@app.route('/read-content')
def read_content():
    url = request.args.get('url')
    if not url: return jsonify({"content": "No URL"}), 400
    content = scrape_article_content(url)
    return jsonify({"content": content})

@app.route('/export')
def export_data():
    data = { "generated_at": datetime.now().isoformat(), "stats": NEWS_CACHE['stats'], "articles": [{k: v for k, v in a.items() if k != 'gradient'} for a in NEWS_CACHE['data']] }
    response = make_response(json.dumps(data, indent=2, default=str))
    response.headers['Content-Disposition'] = 'attachment; filename=cyber_report.json'
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route('/export-csv')
def export_csv():
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Source', 'Title', 'Date', 'Category', 'Severity', 'CVEs', 'Link'])
    for a in NEWS_CACHE['data']:
        cw.writerow([a['source'], a['title'], a['display_date'], a['category'], a['class'], ", ".join(a['cves']), a['link']])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=cyber_report.csv"
    output.headers["Content-type"] = "text/csv"
    return output

if __name__ == '__main__':
    print("Starting Cyber Threat Monitor v59.0...")
    try:
        load_cache()
    except NameError:
        print("Cache function not ready yet, skipping load.")
    app.run(host='0.0.0.0', port=5000, debug=True)
