# 🔐 CipherScan

CipherScan is a cybersecurity-focused web application that analyzes URLs and domains to detect potential threats such as phishing, malware, and suspicious activity.

---

## 🚀 Live Demo

🌐 Frontend: https://cipherscan-live.netlify.app
🔗 Backend API: https://cipherscan.onrender.com

---

## ⚙️ Tech Stack

* Frontend: React (Vite)
* Backend: Node.js, Express
* Database: MongoDB Atlas
* APIs: VirusTotal, Google Safe Browsing, PhishTank, AbuseIPDB

---

## 🔍 Features

* Scan URLs and domains for threats
* Aggregates results from multiple security providers
* AI-based analysis for better insights
* Clean and simple UI
* Real-time scanning results

---

## 🧪 API Usage

### Endpoint:

POST /api/scan

### Request Body:

```json
{
  "target": "https://example.com",
  "type": "url"
}
```

### Response:

```json
{
  "verdict": "safe",
  "confidence": 92,
  "details": {}
}
```

---

## 🛠️ Setup Locally

### Clone the repo

```bash
git clone https://github.com/underscoreriiri/cipherScan.git
cd cipherScan
```

### Backend

```bash
cd backend
npm install
npm run dev
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

---

## 📌 Notes

* Backend may take a few seconds to respond initially (Render free tier cold start)
* Ensure environment variables are configured properly

---

## 👨‍💻 Author

* Riya Singh
* Vedant Singh

---

## ⭐ Support

If you like this project, consider giving it a ⭐ on GitHub!
