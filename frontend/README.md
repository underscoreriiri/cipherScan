# 🔐 CipherScan — Frontend

> A sleek threat intelligence dashboard to scan URLs and IPs with real-time AI analysis.

🌐 **Live Demo:** [cipherscan-live.netlify.app](https://cipherscan-live.netlify.app)

---

## ✨ Features

- 🔍 Scan URLs and IPs with a single click
- 📊 Visual **risk score arc** with AI-powered threat analysis
- 🛡 **Security engine results** from 7+ engines
- 🌍 IP geolocation & vendor verdict display
- 💎 Pricing & API documentation modals
- 📱 Responsive design

---

## 🧰 Tech Stack

| Technology | Usage        |
| ---------- | ------------ |
| React      | UI framework |
| Vite       | Build tool   |
| Netlify    | Deployment   |

---

## 🚀 Setup & Installation

### 1. Clone & Install

```bash
git clone https://github.com/underscoreriiri/cipherScan.git
cd cipherScan/frontend
npm install
```

### 2. Update API URL

In `src/App.jsx` update the backend URL:

```js
const res = await fetch("https://cipherscan.onrender.com/api/scan", {
```

### 3. Run locally

```bash
npm run dev
```

App will start on `http://localhost:5173`

---

## 🏗 Build for Production

```bash
npm run build
```

---

## 👥 Contributors

| Name                                                   | Role                 |
| ------------------------------------------------------ | -------------------- |
| [@ved-ant-singh](https://github.com/ved-ant-singh)     | Backend Integration  |
| [@underscoreriiri](https://github.com/underscoreriiri) | Frontend & UI Design |

---

## 📄 License

Built as a college project. All rights reserved.
