# 🔐 CipherScan — Backend

> REST API for scanning URLs and IP addresses against multiple security engines with real-time AI analysis.

🌐 **Live API:** [cipherscan.onrender.com](https://cipherscan.onrender.com)

---

## ✨ Features

- 🛡 Scans against **7+ security engines**
- 🤖 **AI risk scoring** powered by Google Gemini
- ⚡ **MongoDB caching** — repeat scans return instantly
- 🌍 IP geolocation & vendor verdict aggregation

---

## 🧰 Tech Stack

| Technology           | Usage                  |
| -------------------- | ---------------------- |
| Node.js              | Runtime                |
| Express              | REST API framework     |
| MongoDB              | Result caching         |
| Google Gemini        | AI threat analysis     |
| VirusTotal           | Malware detection      |
| AlienVault OTX       | Threat intelligence    |
| URLHaus              | Malicious URL database |
| PhishTank            | Phishing detection     |
| Google Safe Browsing | Safe browsing API      |
| AbuseIPDB            | IP reputation          |
| Spamhaus             | IP blocklist           |

---

## 🚀 Setup & Installation

### 1. Clone & Install

```bash
git clone https://github.com/underscoreriiri/cipherScan.git
cd cipherScan/backend
npm install
```

### 2. Create `.env` file

```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
VIRUSTOTAL_API_KEY=your_key
GEMINI_API_KEY=your_key
GOOGLE_SAFE_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
```

### 3. Run the server

```bash
npm start
```

Server will start on `http://localhost:5000`

---

## 📡 API Usage

**Endpoint:** `POST /api/scan`

```json
{
  "target": "https://example.com",
  "type": "url"
}
```

**Response:**

```json
{
  "success": true,
  "cached": false,
  "data": {
    "target": "https://example.com",
    "resolvedIP": "93.184.216.34",
    "geo": { "country": "United States" },
    "stats": { "malicious": 0, "harmless": 68 },
    "aiAnalysis": { "riskScore": 4, "threatCategory": "safe" }
  }
}
```

---

## 👥 Contributors

| Name                                                   | Role                |
| ------------------------------------------------------ | ------------------- |
| [@ved-ant-singh](https://github.com/ved-ant-singh)     | Backend Integration |
| [@underscoreriiri](https://github.com/underscoreriiri) | Project Lead        |

---

## 📄 License

Built as a college project. All rights reserved.
