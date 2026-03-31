import { useState, useEffect, useRef } from "react";

const VERDICT_META = {
  clean: {
    label: "Clean",
    color: "#22d3a0",
    bg: "rgba(34,211,160,0.12)",
    glow: "0 0 14px rgba(34,211,160,0.45)",
  },
  safe: {
    label: "Safe",
    color: "#22d3a0",
    bg: "rgba(34,211,160,0.12)",
    glow: "0 0 14px rgba(34,211,160,0.45)",
  },
  suspicious: {
    label: "Suspicious",
    color: "#f5a623",
    bg: "rgba(245,166,35,0.12)",
    glow: "0 0 14px rgba(245,166,35,0.45)",
  },
  malicious: {
    label: "Malicious",
    color: "#ff4d6d",
    bg: "rgba(255,77,109,0.12)",
    glow: "0 0 14px rgba(255,77,109,0.45)",
  },
  unknown: {
    label: "Unknown",
    color: "#6b7a99",
    bg: "rgba(107,122,153,0.10)",
    glow: "none",
  },
};

const ENGINE_ICONS = {
  VirusTotal: "🛡",
  "Google Safe Browsing": "🔍",
  URLHaus: "🕸",
  PhishTank: "🎣",
  "AlienVault OTX": "👽",
  AbuseIPDB: "🚨",
  Spamhaus: "📮",
};

const COUNTRY_CODES = {
  "United States": "US",
  Russia: "RU",
  China: "CN",
  Germany: "DE",
  "United Kingdom": "GB",
  France: "FR",
  Netherlands: "NL",
  Canada: "CA",
  Australia: "AU",
  Japan: "JP",
  India: "IN",
  Brazil: "BR",
  Singapore: "SG",
  "South Korea": "KR",
  Sweden: "SE",
  Ukraine: "UA",
  Iran: "IR",
  "North Korea": "KP",
  Romania: "RO",
  Turkey: "TR",
  Poland: "PL",
  Italy: "IT",
  Spain: "ES",
  Switzerland: "CH",
  Finland: "FI",
  Norway: "NO",
  Denmark: "DK",
  "Czech Republic": "CZ",
  Austria: "AT",
  Belgium: "BE",
};

const FLAG = (country) => {
  const code = COUNTRY_CODES[country];
  if (!code) return "🌐";
  return code
    .toUpperCase()
    .replace(/./g, (c) => String.fromCodePoint(c.charCodeAt(0) + 127397));
};

const CONFIDENCE_META = {
  high: { label: "High Confidence", color: "#22d3a0", icon: "◉" },
  medium: { label: "Medium Confidence", color: "#f5a623", icon: "◎" },
  low: { label: "Low Confidence", color: "#6b7a99", icon: "○" },
};

async function callScanAPI(target, type) {
  const res = await fetch("https://cipherscan.onrender.com/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, type }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.error || "Scan failed");
  }
  return res.json();
}

function RiskArc({ score }) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let start = null;
    const step = (ts) => {
      if (!start) start = ts;
      const p = Math.min((ts - start) / 1400, 1);
      setVal(Math.round((1 - Math.pow(1 - p, 3)) * score));
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [score]);
  const r = 52,
    circ = 2 * Math.PI * r;
  const color = score >= 70 ? "#ff4d6d" : score >= 35 ? "#f5a623" : "#22d3a0";
  return (
    <div style={{ position: "relative", width: 128, height: 128 }}>
      <svg width="128" height="128" style={{ transform: "rotate(-90deg)" }}>
        <circle
          cx="64"
          cy="64"
          r={r}
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth="10"
        />
        <circle
          cx="64"
          cy="64"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={circ - (val / 100) * circ}
          style={{
            filter: `drop-shadow(0 0 7px ${color})`,
            transition: "stroke-dashoffset 0.05s linear",
          }}
        />
      </svg>
      <div
        style={{
          position: "absolute",
          inset: 0,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <span
          style={{
            fontSize: 28,
            fontWeight: 800,
            color,
            fontFamily: "'Share Tech Mono',monospace",
            lineHeight: 1,
          }}
        >
          {val}
        </span>
        <span
          style={{
            fontSize: 10,
            color: "rgba(255,255,255,0.38)",
            letterSpacing: 2,
            marginTop: 2,
            textTransform: "uppercase",
          }}
        >
          risk
        </span>
      </div>
    </div>
  );
}

function Loading({ target }) {
  const steps = [
    "Querying VirusTotal…",
    "Scanning AlienVault OTX…",
    "Checking URLHaus & PhishTank…",
    "Running Google Safe Browsing…",
    "Resolving IP & geolocation…",
    "Running Gemini AI analysis…",
  ];
  const [step, setStep] = useState(0);
  const [pct, setPct] = useState(0);
  useEffect(() => {
    const iv = setInterval(() => setStep((s) => (s + 1) % steps.length), 540);
    return () => clearInterval(iv);
  }, []);
  useEffect(() => {
    let p = 0;
    const iv = setInterval(() => {
      p += Math.random() * 2.8;
      if (p >= 90) {
        clearInterval(iv);
        p = 90;
      }
      setPct(Math.min(p, 90));
    }, 100);
    return () => clearInterval(iv);
  }, []);
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 28,
        padding: "44px 24px",
      }}
    >
      <div style={{ position: "relative", width: 110, height: 110 }}>
        {[0, 12, 24].map((ins, i) => (
          <div
            key={i}
            style={{
              position: "absolute",
              top: ins,
              bottom: ins,
              left: ins,
              right: ins,
              borderRadius: "50%",
              border: `1px solid rgba(34,211,160,${0.15 + i * 0.08})`,
              animation: `ping 1.5s cubic-bezier(0,0,0.2,1) infinite ${i * 0.3}s`,
            }}
          />
        ))}
        <div
          style={{
            position: "absolute",
            inset: 0,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <div
            style={{
              width: 34,
              height: 34,
              borderRadius: "50%",
              background:
                "radial-gradient(circle,rgba(34,211,160,0.85) 0%,rgba(34,211,160,0.18) 70%)",
              boxShadow: "0 0 26px rgba(34,211,160,0.8)",
              animation: "pulse 1s ease-in-out infinite",
            }}
          />
        </div>
        <div
          style={{
            position: "absolute",
            inset: 0,
            borderRadius: "50%",
            background:
              "conic-gradient(from 0deg,rgba(34,211,160,0.15) 0deg,rgba(34,211,160,0) 90deg,transparent 90deg)",
            animation: "spin 2s linear infinite",
          }}
        />
      </div>
      <div
        style={{
          fontFamily: "'Share Tech Mono',monospace",
          fontSize: 12.5,
          color: "#22d3a0",
          padding: "5px 16px",
          border: "1px solid rgba(34,211,160,0.25)",
          borderRadius: 4,
          background: "rgba(34,211,160,0.06)",
          maxWidth: "100%",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
        className="loading-target"
      >
        TARGET: {target}
      </div>
      <div
        style={{
          fontFamily: "'Share Tech Mono',monospace",
          fontSize: 12.5,
          color: "rgba(255,255,255,0.65)",
          height: 20,
          textAlign: "center",
        }}
      >
        <span style={{ color: "#22d3a0" }}>▶</span> {steps[step]}
      </div>
      <div style={{ width: "100%", maxWidth: "min(400px,100%)" }}>
        <div
          style={{
            height: 3,
            background: "rgba(255,255,255,0.06)",
            borderRadius: 2,
            overflow: "hidden",
          }}
        >
          <div
            style={{
              height: "100%",
              width: `${pct}%`,
              background: "linear-gradient(90deg,#22d3a0,#00e5ff)",
              boxShadow: "0 0 12px rgba(34,211,160,0.6)",
              borderRadius: 2,
              transition: "width 0.12s linear",
            }}
          />
        </div>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            marginTop: 5,
          }}
        >
          <span
            style={{
              fontFamily: "'Share Tech Mono',monospace",
              fontSize: 10.5,
              color: "rgba(255,255,255,0.28)",
            }}
          >
            Scanning…
          </span>
          <span
            style={{
              fontFamily: "'Share Tech Mono',monospace",
              fontSize: 10.5,
              color: "#22d3a0",
            }}
          >
            {Math.round(pct)}%
          </span>
        </div>
      </div>
    </div>
  );
}

function SLabel({ children, sub, right }) {
  return (
    <div
      style={{
        marginBottom: 14,
        display: "flex",
        justifyContent: "space-between",
        alignItems: "flex-end",
      }}
    >
      <div>
        <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
          <div
            style={{
              width: 3,
              height: 15,
              background: "#22d3a0",
              borderRadius: 2,
              boxShadow: "0 0 8px #22d3a0",
            }}
          />
          <span
            style={{
              fontSize: 13,
              fontWeight: 700,
              color: "rgba(255,255,255,0.9)",
              letterSpacing: 0.4,
            }}
          >
            {children}
          </span>
        </div>
        {sub && (
          <p
            style={{
              margin: "3px 0 0 12px",
              fontSize: 11.5,
              color: "rgba(255,255,255,0.28)",
            }}
          >
            {sub}
          </p>
        )}
      </div>
      {right}
    </div>
  );
}

function TargetIntel({ data, scanTarget, scanType }) {
  const { resolvedIP, geo, vendors, attributes } = data;
  const country = geo?.country || "Unknown";
  const flagEmoji = FLAG(country);

  const InfoRow = ({ label, value, accent, mono }) => (
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        padding: "9px 0",
        borderBottom: "1px solid rgba(255,255,255,0.05)",
      }}
    >
      <span
        style={{
          fontSize: 11.5,
          color: "rgba(255,255,255,0.35)",
          fontFamily: "'Share Tech Mono',monospace",
          letterSpacing: 1,
        }}
      >
        {label}
      </span>
      <span
        className="info-row-val"
        style={{
          fontSize: 13,
          fontWeight: 600,
          color: accent || "rgba(255,255,255,0.82)",
          fontFamily: mono
            ? "'Share Tech Mono',monospace"
            : "'Syne',sans-serif",
        }}
      >
        {value ?? "—"}
      </span>
    </div>
  );

  const lastAnalysis = attributes?.lastAnalysisDate
    ? new Date(attributes.lastAnalysisDate).toLocaleDateString("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric",
      })
    : null;

  return (
    <div
      className="intel-g"
      style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}
    >
      <div
        style={{
          background: "rgba(255,255,255,0.03)",
          border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 14,
          padding: "20px 22px",
        }}
      >
        <div
          style={{
            fontFamily: "'Share Tech Mono',monospace",
            fontSize: 9.5,
            color: "#22d3a0",
            letterSpacing: 3,
            marginBottom: 14,
          }}
        >
          ◈ IP &amp; GEOLOCATION
        </div>
        <InfoRow label="TARGET" value={scanTarget} />
        <InfoRow
          label="RESOLVED IP"
          value={resolvedIP || "Unresolved"}
          accent={resolvedIP ? "#22d3a0" : "#6b7a99"}
          mono
        />
        <InfoRow
          label="COUNTRY"
          value={resolvedIP || geo?.country ? `${flagEmoji}  ${country}` : "—"}
        />
        <InfoRow label="SCAN TYPE" value={scanType?.toUpperCase()} />
      </div>

      <div
        style={{
          background: "rgba(255,255,255,0.03)",
          border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 14,
          padding: "20px 22px",
        }}
      >
        <div
          style={{
            fontFamily: "'Share Tech Mono',monospace",
            fontSize: 9.5,
            color: "#22d3a0",
            letterSpacing: 3,
            marginBottom: 14,
          }}
        >
          ◈ SCAN ATTRIBUTES
        </div>
        <InfoRow
          label="HTTP STATUS"
          value={attributes?.statusCode ? `${attributes.statusCode}` : "—"}
          accent={
            attributes?.statusCode >= 400
              ? "#ff4d6d"
              : attributes?.statusCode
                ? "#22d3a0"
                : undefined
          }
        />
        <InfoRow
          label="CONTENT TYPE"
          value={attributes?.contentType?.split(";")[0] || "—"}
        />
        <InfoRow label="LAST ANALYZED" value={lastAnalysis || "—"} />
        <InfoRow
          label="TRACKERS"
          value={
            attributes?.trackersCount != null
              ? `${attributes.trackersCount} detected`
              : "—"
          }
          accent={attributes?.trackersCount > 0 ? "#f5a623" : undefined}
        />
        <InfoRow
          label="IFRAMES"
          value={
            attributes?.iframesCount != null
              ? `${attributes.iframesCount} found`
              : "—"
          }
          accent={attributes?.iframesCount > 0 ? "#f5a623" : undefined}
        />
      </div>

      <div
        style={{
          gridColumn: "1/-1",
          background: "rgba(255,255,255,0.03)",
          border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 14,
          padding: "20px 22px",
        }}
      >
        <div
          style={{
            fontFamily: "'Share Tech Mono',monospace",
            fontSize: 9.5,
            color: "#22d3a0",
            letterSpacing: 3,
            marginBottom: 14,
          }}
        >
          ◈ VIRUSTOTAL VENDORS THAT FLAGGED THIS TARGET
          {vendors?.count > 0 && (
            <span
              style={{
                marginLeft: 12,
                fontSize: 11,
                color: "#ff4d6d",
                background: "rgba(255,77,109,0.1)",
                border: "1px solid rgba(255,77,109,0.25)",
                borderRadius: 4,
                padding: "1px 8px",
                letterSpacing: 0,
              }}
            >
              {vendors.count} vendor{vendors.count !== 1 ? "s" : ""}
            </span>
          )}
        </div>
        {!vendors?.names?.length ? (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "10px 0",
            }}
          >
            <span style={{ fontSize: 20 }}>✅</span>
            <span style={{ fontSize: 13.5, color: "rgba(255,255,255,0.5)" }}>
              No VirusTotal vendors flagged this target
            </span>
          </div>
        ) : (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 9 }}>
            {vendors.names.map((name, i) => (
              <div
                key={i}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  background: "rgba(255,77,109,0.08)",
                  border: "1px solid rgba(255,77,109,0.22)",
                  borderLeft: "3px solid #ff4d6d",
                  borderRadius: 8,
                  padding: "8px 14px",
                  transition: "all 0.2s",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = "rgba(255,77,109,0.14)";
                  e.currentTarget.style.transform = "translateY(-1px)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "rgba(255,77,109,0.08)";
                  e.currentTarget.style.transform = "none";
                }}
              >
                <div
                  style={{
                    width: 7,
                    height: 7,
                    borderRadius: "50%",
                    background: "#ff4d6d",
                    boxShadow: "0 0 7px #ff4d6d",
                    flexShrink: 0,
                  }}
                />
                <span
                  style={{
                    fontSize: 12.5,
                    fontWeight: 600,
                    color: "rgba(255,255,255,0.82)",
                  }}
                >
                  {name}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function APIModal({ onClose }) {
  const [tab, setTab] = useState("quickstart");
  const [lang, setLang] = useState("curl");
  const [keyCopied, setKeyCopied] = useState(false);

  const TABS = [
    { id: "quickstart", label: "Quickstart" },
    { id: "endpoints", label: "API Endpoints" },
    { id: "response", label: "Response Schema" },
    { id: "envvars", label: "Env Variables" },
  ];

  const ENDPOINTS = [
    {
      method: "POST",
      path: "/api/scan",
      desc: "Submit a URL or IP for scanning",
      auth: false,
    },
  ];
  const METHOD_COLOR = { POST: "#22d3a0", GET: "#0091ff", DELETE: "#ff4d6d" };

  const SNIPPETS = {
    curl: `# Scan a URL\ncurl -X POST https://cipherscan.onrender.com/api/scan \\\n  -H "Content-Type: application/json" \\\n  -d '{"target":"https://example.com","type":"url"}'\n\n# Scan an IP address\ncurl -X POST "https://cipherscan.onrender.com/api/scan \\\n  -H "Content-Type: application/json" \\\n  -d '{"target":"192.168.1.1","type":"ip"}'`,
    javascript: `const BASE = "https://cipherscan.onrender.com";\n\nasync function scan(target, type = "url") {\n  const res = await fetch(\`\${BASE}/api/scan\`, {\n    method: "POST",\n    headers: { "Content-Type": "application/json" },\n    body: JSON.stringify({ target, type }),\n  });\n  const json = await res.json();\n  if (!json.success) throw new Error(json.error);\n  return json.data;\n}\n\nconst data = await scan("https://example.com", "url");\nconsole.log("Risk Score:", data.aiAnalysis.riskScore);`,
    python: `import requests\n\nBASE = "https://cipherscan.onrender.com"\n\ndef scan(target, scan_type="url"):\n    resp = requests.post(\n        f"{BASE}/api/scan",\n        json={"target": target, "type": scan_type}\n    )\n    resp.raise_for_status()\n    json_data = resp.json()\n    if not json_data["success"]:\n        raise Exception(json_data.get("error", "Scan failed"))\n    return json_data["data"]\n\ndata = scan("https://example.com", "url")\nprint(f"Risk Score: {data['aiAnalysis']['riskScore']}")`,
  };

  const ENV_VARS = [
    { key: "PORT", example: "5000", desc: "Server port", required: false },
    {
      key: "MONGO_URI",
      example: "mongodb://...",
      desc: "MongoDB connection string",
      required: true,
    },
    {
      key: "VIRUSTOTAL_API_KEY",
      example: "vt_xxx...",
      desc: "VirusTotal API key",
      required: true,
    },
    {
      key: "GEMINI_API_KEY",
      example: "AIzaSy...",
      desc: "Google Gemini AI key",
      required: true,
    },
    {
      key: "GOOGLE_SAFE_API_KEY",
      example: "AIzaSy...",
      desc: "Google Safe Browsing API key",
      required: true,
    },
    {
      key: "ABUSEIPDB_API_KEY",
      example: "abc123...",
      desc: "AbuseIPDB API key (IP scans)",
      required: false,
    },
  ];

  return (
    <div
      style={{ position: "fixed", inset: 0, zIndex: 1000, display: "flex" }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        style={{
          position: "absolute",
          inset: 0,
          background: "rgba(4,11,20,0.88)",
          backdropFilter: "blur(6px)",
        }}
        onClick={onClose}
      />
      <div
        style={{
          position: "absolute",
          top: 0,
          right: 0,
          bottom: 0,
          width: "min(700px,95vw)",
          background: "linear-gradient(160deg,#07111f 0%,#040b14 100%)",
          borderLeft: "1px solid rgba(34,211,160,0.18)",
          boxShadow: "-20px 0 80px rgba(0,0,0,0.6)",
          display: "flex",
          flexDirection: "column",
          animation: "slideInRight 0.3s cubic-bezier(0.22,1,0.36,1)",
          overflow: "hidden",
        }}
        className="modal-panel"
      >
        <div
          style={{
            padding: "22px 28px",
            borderBottom: "1px solid rgba(255,255,255,0.07)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexShrink: 0,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div
              style={{
                width: 34,
                height: 34,
                borderRadius: 8,
                background:
                  "linear-gradient(135deg,rgba(34,211,160,0.2),rgba(0,145,255,0.2))",
                border: "1px solid rgba(34,211,160,0.3)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 16,
              }}
            >
              ⚡
            </div>
            <div>
              <div style={{ fontSize: 16, fontWeight: 800 }}>
                CipherScan <span style={{ color: "#22d3a0" }}>API</span>
              </div>
              <div
                style={{
                  fontFamily: "'Share Tech Mono',monospace",
                  fontSize: 9,
                  color: "rgba(255,255,255,0.3)",
                  letterSpacing: 2,
                }}
              >
                DEVELOPER REFERENCE v1.0.0
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "rgba(255,255,255,0.06)",
              border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 8,
              width: 34,
              height: 34,
              color: "rgba(255,255,255,0.5)",
              fontSize: 16,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              transition: "all 0.2s",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "rgba(255,77,109,0.15)";
              e.currentTarget.style.color = "#ff4d6d";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "rgba(255,255,255,0.06)";
              e.currentTarget.style.color = "rgba(255,255,255,0.5)";
            }}
          >
            ✕
          </button>
        </div>

        <div
          style={{
            margin: "14px 28px 0",
            background: "rgba(0,145,255,0.06)",
            border: "1px solid rgba(0,145,255,0.2)",
            borderRadius: 10,
            padding: "11px 16px",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexShrink: 0,
          }}
        >
          <div>
            <div
              style={{
                fontFamily: "'Share Tech Mono',monospace",
                fontSize: 9.5,
                color: "rgba(255,255,255,0.32)",
                letterSpacing: 2,
                marginBottom: 3,
              }}
            >
              BASE URL
            </div>
            <code
              style={{
                fontFamily: "'Share Tech Mono',monospace",
                fontSize: 13,
                color: "#60b4ff",
              }}
            >
              https://cipherscan.onrender.com/api/scan
            </code>
          </div>
          <button
            onClick={() => {
              navigator.clipboard?.writeText(
                `https://cipherscan.onrender.com/api/scan`,
              );
              setKeyCopied(true);
              setTimeout(() => setKeyCopied(false), 2000);
            }}
            style={{
              background: "rgba(0,145,255,0.1)",
              border: "1px solid rgba(0,145,255,0.25)",
              borderRadius: 6,
              padding: "5px 13px",
              color: keyCopied ? "#22d3a0" : "rgba(255,255,255,0.45)",
              fontSize: 11,
              cursor: "pointer",
              fontFamily: "'Share Tech Mono',monospace",
              transition: "color 0.2s",
            }}
          >
            {keyCopied ? "✓ Copied" : "Copy"}
          </button>
        </div>

        <div
          className="modal-tabs"
          style={{
            display: "flex",
            gap: 2,
            padding: "14px 28px 0",
            flexShrink: 0,
          }}
        >
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              style={{
                padding: "7px 13px",
                borderRadius: "8px 8px 0 0",
                background:
                  tab === t.id ? "rgba(34,211,160,0.1)" : "transparent",
                border:
                  tab === t.id
                    ? "1px solid rgba(34,211,160,0.22)"
                    : "1px solid transparent",
                borderBottom: tab === t.id ? "1px solid #07111f" : undefined,
                color: tab === t.id ? "#22d3a0" : "rgba(255,255,255,0.36)",
                fontSize: 12.5,
                fontWeight: 600,
                cursor: "pointer",
                transition: "all 0.18s",
                fontFamily: "'Syne',sans-serif",
              }}
            >
              {t.label}
            </button>
          ))}
        </div>
        <div
          style={{
            margin: "0 28px",
            borderBottom: "1px solid rgba(34,211,160,0.18)",
          }}
        />

        <div style={{ flex: 1, overflowY: "auto", padding: "22px 28px 28px" }}>
          {tab === "quickstart" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
              <p
                style={{
                  fontSize: 13.5,
                  color: "rgba(255,255,255,0.55)",
                  lineHeight: 1.75,
                }}
              >
                POST{" "}
                <code
                  style={{
                    fontFamily: "'Share Tech Mono',monospace",
                    color: "#22d3a0",
                    fontSize: 12,
                  }}
                >
                  /api/scan
                </code>{" "}
                with a target and type. No authentication required — API keys
                live in the server's{" "}
                <code
                  style={{
                    fontFamily: "'Share Tech Mono',monospace",
                    color: "#f5a623",
                    fontSize: 12,
                  }}
                >
                  .env
                </code>{" "}
                file. Results are cached in MongoDB — repeat scans return
                instantly.
              </p>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: 10,
                }}
              >
                {[
                  {
                    type: "url",
                    engines: [
                      "VirusTotal",
                      "AlienVault OTX",
                      "URLHaus",
                      "Google Safe Browsing",
                      "PhishTank",
                    ],
                    color: "#22d3a0",
                  },
                  {
                    type: "ip",
                    engines: [
                      "VirusTotal",
                      "AlienVault OTX",
                      "AbuseIPDB",
                      "Spamhaus",
                    ],
                    color: "#0091ff",
                  },
                ].map((sc) => (
                  <div
                    key={sc.type}
                    style={{
                      background: "rgba(255,255,255,0.03)",
                      border: `1px solid ${sc.color}25`,
                      borderRadius: 10,
                      padding: "14px 16px",
                    }}
                  >
                    <div
                      style={{
                        fontFamily: "'Share Tech Mono',monospace",
                        fontSize: 9.5,
                        color: sc.color,
                        letterSpacing: 2,
                        marginBottom: 8,
                      }}
                    >
                      TYPE: {sc.type.toUpperCase()}
                    </div>
                    {sc.engines.map((e, i) => (
                      <div
                        key={i}
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 6,
                          marginBottom: 4,
                        }}
                      >
                        <span style={{ fontSize: 12 }}>
                          {ENGINE_ICONS[e] || "🔒"}
                        </span>
                        <span
                          style={{
                            fontSize: 11.5,
                            color: "rgba(255,255,255,0.55)",
                          }}
                        >
                          {e}
                        </span>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
              <div style={{ display: "flex", gap: 6 }}>
                {["curl", "javascript", "python"].map((l) => (
                  <button
                    key={l}
                    onClick={() => setLang(l)}
                    style={{
                      padding: "5px 13px",
                      borderRadius: 6,
                      background:
                        lang === l
                          ? "rgba(34,211,160,0.12)"
                          : "rgba(255,255,255,0.04)",
                      border:
                        lang === l
                          ? "1px solid rgba(34,211,160,0.28)"
                          : "1px solid rgba(255,255,255,0.08)",
                      color: lang === l ? "#22d3a0" : "rgba(255,255,255,0.4)",
                      fontSize: 11.5,
                      cursor: "pointer",
                      fontFamily: "'Share Tech Mono',monospace",
                      transition: "all 0.15s",
                    }}
                  >
                    {l}
                  </button>
                ))}
              </div>
              <div
                style={{
                  background: "rgba(0,0,0,0.45)",
                  border: "1px solid rgba(255,255,255,0.07)",
                  borderRadius: 10,
                  overflow: "hidden",
                }}
              >
                <div
                  style={{
                    padding: "8px 14px",
                    borderBottom: "1px solid rgba(255,255,255,0.06)",
                    fontFamily: "'Share Tech Mono',monospace",
                    fontSize: 9.5,
                    color: "rgba(255,255,255,0.22)",
                    letterSpacing: 2,
                  }}
                >
                  {lang.toUpperCase()} EXAMPLE
                </div>
                <pre
                  style={{
                    margin: 0,
                    padding: "16px 18px",
                    fontSize: 11.5,
                    lineHeight: 1.75,
                    color: "#a8d8c8",
                    fontFamily: "'Share Tech Mono',monospace",
                    overflow: "auto",
                  }}
                >
                  {SNIPPETS[lang]}
                </pre>
              </div>
            </div>
          )}

          {tab === "endpoints" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {ENDPOINTS.map((ep, i) => (
                <div
                  key={i}
                  style={{
                    background: "rgba(255,255,255,0.03)",
                    border: "1px solid rgba(255,255,255,0.07)",
                    borderRadius: 10,
                    padding: "16px",
                    transition: "all 0.18s",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = "rgba(34,211,160,0.2)";
                    e.currentTarget.style.background = "rgba(34,211,160,0.03)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor =
                      "rgba(255,255,255,0.07)";
                    e.currentTarget.style.background = "rgba(255,255,255,0.03)";
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 12,
                      marginBottom: 12,
                    }}
                  >
                    <span
                      style={{
                        fontFamily: "'Share Tech Mono',monospace",
                        fontSize: 11,
                        fontWeight: 700,
                        color: METHOD_COLOR[ep.method] || "#22d3a0",
                        background: `${METHOD_COLOR[ep.method] || "#22d3a0"}15`,
                        border: `1px solid ${METHOD_COLOR[ep.method] || "#22d3a0"}35`,
                        borderRadius: 4,
                        padding: "2px 9px",
                      }}
                    >
                      {ep.method}
                    </span>
                    <code
                      style={{
                        fontFamily: "'Share Tech Mono',monospace",
                        fontSize: 13,
                        color: "rgba(255,255,255,0.82)",
                      }}
                    >
                      {ep.path}
                    </code>
                  </div>
                  <p
                    style={{
                      fontSize: 12.5,
                      color: "rgba(255,255,255,0.45)",
                      margin: "0 0 12px",
                    }}
                  >
                    {ep.desc}
                  </p>
                  <div
                    style={{
                      background: "rgba(0,0,0,0.3)",
                      borderRadius: 8,
                      padding: "12px 14px",
                    }}
                  >
                    <div
                      style={{
                        fontFamily: "'Share Tech Mono',monospace",
                        fontSize: 9.5,
                        color: "rgba(255,255,255,0.25)",
                        letterSpacing: 2,
                        marginBottom: 6,
                      }}
                    >
                      REQUEST BODY
                    </div>
                    <pre
                      style={{
                        margin: 0,
                        fontSize: 11.5,
                        lineHeight: 1.7,
                        color: "#a8d8c8",
                        fontFamily: "'Share Tech Mono',monospace",
                      }}
                    >
                      {`{
  "target": "https://example.com",
  "type": "url"
}`}
                    </pre>
                  </div>
                </div>
              ))}
              <div
                style={{
                  background: "rgba(34,211,160,0.06)",
                  border: "1px solid rgba(34,211,160,0.18)",
                  borderRadius: 10,
                  padding: "13px 16px",
                  fontSize: 12.5,
                  color: "rgba(255,255,255,0.5)",
                  lineHeight: 1.65,
                }}
              >
                📦 Results are{" "}
                <strong style={{ color: "#22d3a0" }}>cached in MongoDB</strong>.
                Duplicate scans return instantly with{" "}
                <code
                  style={{
                    fontFamily: "'Share Tech Mono',monospace",
                    color: "#22d3a0",
                    fontSize: 11,
                  }}
                >
                  cached: true
                </code>
                .
              </div>
            </div>
          )}

          {tab === "response" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <p
                style={{
                  fontSize: 13,
                  color: "rgba(255,255,255,0.45)",
                  lineHeight: 1.7,
                }}
              >
                The response wraps all scan data under{" "}
                <code
                  style={{
                    color: "#22d3a0",
                    fontFamily: "'Share Tech Mono',monospace",
                    fontSize: 12,
                  }}
                >
                  data
                </code>
                . Check{" "}
                <code
                  style={{
                    color: "#f5a623",
                    fontFamily: "'Share Tech Mono',monospace",
                    fontSize: 12,
                  }}
                >
                  cached
                </code>{" "}
                to know if the result came from the database.
              </p>
              <div
                style={{
                  background: "rgba(0,0,0,0.45)",
                  border: "1px solid rgba(255,255,255,0.07)",
                  borderRadius: 10,
                  overflow: "hidden",
                }}
              >
                <pre
                  style={{
                    margin: 0,
                    padding: "18px 20px",
                    fontSize: 11.5,
                    lineHeight: 1.8,
                    color: "#a8d8c8",
                    fontFamily: "'Share Tech Mono',monospace",
                    overflow: "auto",
                  }}
                >
                  {`{
  "success": true,
  "cached": false,
  "data": {
    "target": "https://example.com",
    "type": "url",
    "resolvedIP": "93.184.216.34",
    "geo": { "country": "United States" },
    "stats": { "malicious": 0, "harmless": 68, "suspicious": 0, "undetected": 27 },
    "attributes": { "statusCode": 200, "contentType": "text/html", "lastAnalysisDate": "2026-03-28T12:00:00Z", "trackersCount": 0, "iframesCount": 0 },
    "vendorVerdict": { "flagged": 0, "total": 95, "percentage": 0, "label": "Safe", "color": "green" },
    "vendors": { "count": 0, "names": [] },
    "engineResults": [
      { "engine": "VirusTotal", "verdict": "clean" },
      { "engine": "AlienVault OTX", "verdict": "clean" }
    ],
    "aiAnalysis": { "riskScore": 4, "threatCategory": "safe", "confidence": "high", "summary": "...", "keyInsights": ["..."], "recommendations": ["..."] },
    "createdAt": "2026-03-28T12:00:00Z",
    "updatedAt": "2026-03-28T12:00:00Z"
  }
}`}
                </pre>
              </div>
            </div>
          )}

          {tab === "envvars" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <p
                style={{
                  fontSize: 13,
                  color: "rgba(255,255,255,0.45)",
                  lineHeight: 1.7,
                  marginBottom: 4,
                }}
              >
                Copy{" "}
                <code
                  style={{
                    fontFamily: "'Share Tech Mono',monospace",
                    color: "#22d3a0",
                    fontSize: 12,
                  }}
                >
                  .env.example
                </code>{" "}
                to{" "}
                <code
                  style={{
                    fontFamily: "'Share Tech Mono',monospace",
                    color: "#22d3a0",
                    fontSize: 12,
                  }}
                >
                  .env
                </code>{" "}
                and fill in your keys.
              </p>
              {ENV_VARS.map((v, i) => (
                <div
                  key={i}
                  style={{
                    background: "rgba(255,255,255,0.03)",
                    border: `1px solid ${v.required ? "rgba(34,211,160,0.18)" : "rgba(255,255,255,0.07)"}`,
                    borderRadius: 10,
                    padding: "13px 16px",
                    display: "grid",
                    gridTemplateColumns: "1fr auto",
                    gap: 8,
                    alignItems: "start",
                  }}
                >
                  <div>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                        marginBottom: 4,
                      }}
                    >
                      <code
                        style={{
                          fontFamily: "'Share Tech Mono',monospace",
                          fontSize: 12.5,
                          color: "#22d3a0",
                        }}
                      >
                        {v.key}
                      </code>
                      {v.required && (
                        <span
                          style={{
                            fontSize: 9.5,
                            fontFamily: "'Share Tech Mono',monospace",
                            color: "#ff4d6d",
                            background: "rgba(255,77,109,0.1)",
                            border: "1px solid rgba(255,77,109,0.25)",
                            borderRadius: 4,
                            padding: "1px 6px",
                          }}
                        >
                          REQUIRED
                        </span>
                      )}
                    </div>
                    <div
                      style={{ fontSize: 12, color: "rgba(255,255,255,0.4)" }}
                    >
                      {v.desc}
                    </div>
                  </div>
                  <code
                    style={{
                      fontFamily: "'Share Tech Mono',monospace",
                      fontSize: 11,
                      color: "rgba(255,255,255,0.28)",
                      marginTop: 2,
                    }}
                  >
                    {v.example}
                  </code>
                </div>
              ))}
              <div
                style={{
                  background: "rgba(245,166,35,0.07)",
                  border: "1px solid rgba(245,166,35,0.18)",
                  borderRadius: 10,
                  padding: "12px 16px",
                  fontSize: 12.5,
                  color: "rgba(255,255,255,0.5)",
                  lineHeight: 1.65,
                }}
              >
                ⚠ Never commit your{" "}
                <code
                  style={{
                    fontFamily: "'Share Tech Mono',monospace",
                    color: "#f5a623",
                    fontSize: 11,
                  }}
                >
                  .env
                </code>{" "}
                file. The backend's{" "}
                <code
                  style={{
                    fontFamily: "'Share Tech Mono',monospace",
                    color: "#f5a623",
                    fontSize: 11,
                  }}
                >
                  .gitignore
                </code>{" "}
                already excludes it.
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function PricingModal({ onClose }) {
  const [billing, setBilling] = useState("annual");

  const PLANS = [
    {
      name: "Free",
      icon: "🔓",
      color: "#6b7a99",
      monthly: 0,
      annualMo: 0,
      annual: 0,
      modules: ["API Only"],
      features: [
        "10 private scans/day",
        "50 unlisted scans/day",
        "100 public scans/day",
        "200 search requests",
        "500 result requests",
        "Basic threat intel",
      ],
      cta: "Get Started",
      popular: false,
    },
    {
      name: "Automate",
      icon: "⚙️",
      color: "#0091ff",
      monthly: null,
      annualMo: 499,
      annual: 5999,
      modules: ["API Only"],
      features: [
        "100 private scans/day",
        "300 unlisted scans/day",
        "500 public scans/day",
        "1,000 search requests",
        "2,000 result requests",
        "Webhook integrations",
        "Email alerts",
      ],
      cta: "Start Trial",
      popular: false,
    },
    {
      name: "Professional",
      icon: "🏆",
      color: "#22d3a0",
      monthly: 1499,
      annualMo: 1249,
      annual: 14999,
      modules: ["API", "Threat Hunting"],
      features: [
        "500 private scans/day",
        "1,000 unlisted scans/day",
        "2,000 public scans/day",
        "5,000 search requests",
        "10,000 result requests",
        "AI risk analysis",
        "Priority email support",
        "API access",
      ],
      cta: "Start Trial",
      popular: false,
    },
    {
      name: "Enterprise",
      icon: "🏢",
      color: "#f5a623",
      monthly: 2999,
      annualMo: 2499,
      annual: 29999,
      modules: ["API", "Threat Hunting"],
      features: [
        "1,000 private scans/day",
        "2,500 unlisted scans/day",
        "5,000 public scans/day",
        "15,000 search requests",
        "25,000 result requests",
        "Advanced AI analysis",
        "Team management (5 users)",
        "Priority support",
      ],
      cta: "Contact Sales",
      popular: true,
    },
    {
      name: "Ultimate",
      icon: "⚡",
      color: "#ff4d6d",
      monthly: 4999,
      annualMo: 4166,
      annual: 49999,
      modules: ["API", "Threat Hunting"],
      features: [
        "2,500 private scans/day",
        "5,000 unlisted scans/day",
        "10,000 public scans/day",
        "30,000 search requests",
        "50,000 result requests",
        "Full AI suite",
        "Team management (15 users)",
        "Dedicated account manager",
        "Custom integrations",
      ],
      cta: "Contact Sales",
      popular: false,
    },
  ];

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 1000,
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
        background: "rgba(4,11,20,0.92)",
        backdropFilter: "blur(8px)",
        overflowY: "auto",
        overflowX: "hidden",
        padding: "24px 12px 60px",
        WebkitOverflowScrolling: "touch",
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: 1100,
          animation: "fadeSlideUp 0.3s ease",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          style={{
            textAlign: "center",
            marginBottom: 34,
            position: "relative",
          }}
        >
          <button
            onClick={onClose}
            style={{
              position: "absolute",
              right: 0,
              top: 0,
              background: "rgba(255,255,255,0.06)",
              border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 8,
              width: 36,
              height: 36,
              color: "rgba(255,255,255,0.5)",
              fontSize: 16,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              transition: "all 0.2s",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "rgba(255,77,109,0.15)";
              e.currentTarget.style.color = "#ff4d6d";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "rgba(255,255,255,0.06)";
              e.currentTarget.style.color = "rgba(255,255,255,0.5)";
            }}
          >
            ✕
          </button>
          <div
            style={{
              fontFamily: "'Share Tech Mono',monospace",
              fontSize: 11,
              color: "#22d3a0",
              letterSpacing: 4,
              marginBottom: 10,
            }}
          >
            ✦ CIPHERSCAN PLANS
          </div>
          <h2
            style={{
              fontSize: 36,
              fontWeight: 800,
              letterSpacing: -1.5,
              marginBottom: 10,
            }}
          >
            Choose Your{" "}
            <span
              style={{
                background: "linear-gradient(120deg,#22d3a0,#0091ff)",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
              }}
            >
              Intelligence Level
            </span>
          </h2>
          <p
            style={{
              fontSize: 14.5,
              color: "rgba(255,255,255,0.38)",
              marginBottom: 24,
            }}
          >
            All plans integrate with major SOAR and Threat Intelligence
            platforms.
          </p>
          <div
            style={{
              display: "inline-flex",
              background: "rgba(255,255,255,0.05)",
              border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 100,
              padding: 4,
              gap: 2,
            }}
          >
            {["monthly", "annual"].map((b) => (
              <button
                key={b}
                onClick={() => setBilling(b)}
                style={{
                  padding: "7px 20px",
                  borderRadius: 100,
                  background:
                    billing === b ? "rgba(34,211,160,0.15)" : "transparent",
                  border:
                    billing === b
                      ? "1px solid rgba(34,211,160,0.3)"
                      : "1px solid transparent",
                  color: billing === b ? "#22d3a0" : "rgba(255,255,255,0.4)",
                  fontSize: 12.5,
                  fontWeight: 600,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  transition: "all 0.2s",
                  fontFamily: "'Syne',sans-serif",
                }}
              >
                {b === "annual" ? "Annual" : "Monthly"}
                {b === "annual" && (
                  <span
                    style={{
                      fontSize: 10,
                      background: "#22d3a020",
                      border: "1px solid #22d3a040",
                      borderRadius: 100,
                      padding: "1px 7px",
                      color: "#22d3a0",
                    }}
                  >
                    Save ~17%
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill,minmax(192px,1fr))",
            gap: 13,
          }}
          className="pricing-grid"
        >
          {PLANS.map((plan, i) => (
            <div
              key={i}
              style={{
                background: plan.popular
                  ? "linear-gradient(160deg,rgba(245,166,35,0.1) 0%,rgba(255,77,109,0.05) 100%)"
                  : "rgba(255,255,255,0.03)",
                border: plan.popular
                  ? `1px solid rgba(245,166,35,0.35)`
                  : "1px solid rgba(255,255,255,0.07)",
                borderRadius: 16,
                padding: "22px 18px",
                position: "relative",
                transition: "transform 0.2s,box-shadow 0.2s",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = "translateY(-4px)";
                e.currentTarget.style.boxShadow = `0 16px 40px ${plan.color}18`;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = "none";
                e.currentTarget.style.boxShadow = "none";
              }}
            >
              {plan.popular && (
                <div
                  style={{
                    position: "absolute",
                    top: -12,
                    left: "50%",
                    transform: "translateX(-50%)",
                    background: "linear-gradient(90deg,#f5a623,#ff7043)",
                    borderRadius: 100,
                    padding: "3px 14px",
                    fontSize: 10.5,
                    fontWeight: 700,
                    color: "#fff",
                    boxShadow: "0 4px 16px rgba(245,166,35,0.4)",
                    whiteSpace: "nowrap",
                  }}
                >
                  ⭐ Popular
                </div>
              )}
              <div style={{ fontSize: 22, marginBottom: 10 }}>{plan.icon}</div>
              <div
                style={{
                  fontSize: 18,
                  fontWeight: 800,
                  color: plan.color,
                  marginBottom: 7,
                }}
              >
                {plan.name}
              </div>
              <div
                style={{
                  display: "flex",
                  gap: 5,
                  marginBottom: 16,
                  flexWrap: "wrap",
                }}
              >
                {plan.modules.map((m, j) => (
                  <span
                    key={j}
                    style={{
                      fontSize: 9.5,
                      fontFamily: "'Share Tech Mono',monospace",
                      color: m === "Threat Hunting" ? "#f5a623" : "#0091ff",
                      background:
                        m === "Threat Hunting"
                          ? "rgba(245,166,35,0.1)"
                          : "rgba(0,145,255,0.1)",
                      border:
                        m === "Threat Hunting"
                          ? "1px solid rgba(245,166,35,0.25)"
                          : "1px solid rgba(0,145,255,0.25)",
                      borderRadius: 4,
                      padding: "2px 7px",
                    }}
                  >
                    {m}
                  </span>
                ))}
              </div>
              <div style={{ marginBottom: 18 }}>
                {plan.name === "Free" ? (
                  <div
                    style={{
                      fontSize: 30,
                      fontWeight: 800,
                      fontFamily: "'Share Tech Mono',monospace",
                      color: "#fff",
                    }}
                  >
                    ₹0
                  </div>
                ) : plan.name === "Automate" && billing === "monthly" ? (
                  <div
                    style={{
                      fontSize: 13,
                      color: "rgba(255,255,255,0.38)",
                      fontFamily: "'Share Tech Mono',monospace",
                      lineHeight: 1.6,
                    }}
                  >
                    N/A monthly
                    <br />
                    <span style={{ fontSize: 11 }}>Annual only</span>
                  </div>
                ) : (
                  <>
                    <div
                      style={{
                        fontSize: 28,
                        fontWeight: 800,
                        fontFamily: "'Share Tech Mono',monospace",
                        color: "#fff",
                        lineHeight: 1,
                      }}
                    >
                      ₹
                      {billing === "annual"
                        ? plan.annualMo?.toLocaleString()
                        : plan.monthly?.toLocaleString()}
                      <span
                        style={{
                          fontSize: 12,
                          color: "rgba(255,255,255,0.3)",
                          fontWeight: 400,
                        }}
                      >
                        /mo
                      </span>
                    </div>
                    {billing === "annual" && (
                      <div
                        style={{
                          fontSize: 11,
                          color: "rgba(255,255,255,0.3)",
                          marginTop: 3,
                          fontFamily: "'Share Tech Mono',monospace",
                        }}
                      >
                        ₹{plan.annual?.toLocaleString()}/yr
                      </div>
                    )}
                  </>
                )}
              </div>
              <ul
                style={{
                  listStyle: "none",
                  padding: 0,
                  margin: "0 0 18px",
                  display: "flex",
                  flexDirection: "column",
                  gap: 7,
                }}
              >
                {plan.features.map((f, j) => (
                  <li
                    key={j}
                    style={{
                      display: "flex",
                      gap: 7,
                      alignItems: "flex-start",
                    }}
                  >
                    <span
                      style={{
                        color: plan.color,
                        fontSize: 11,
                        marginTop: 2,
                        flexShrink: 0,
                      }}
                    >
                      ✓
                    </span>
                    <span
                      style={{
                        fontSize: 11.5,
                        color: "rgba(255,255,255,0.52)",
                        lineHeight: 1.45,
                      }}
                    >
                      {f}
                    </span>
                  </li>
                ))}
              </ul>
              <button
                style={{
                  width: "100%",
                  background: plan.popular
                    ? `linear-gradient(135deg,${plan.color},#ff7043)`
                    : `${plan.color}18`,
                  border: `1px solid ${plan.color}45`,
                  borderRadius: 9,
                  padding: "10px 0",
                  color: plan.popular ? "#fff" : plan.color,
                  fontSize: 13,
                  fontWeight: 700,
                  cursor: "pointer",
                  transition: "all 0.2s",
                  fontFamily: "'Syne',sans-serif",
                  boxShadow: plan.popular
                    ? `0 4px 20px ${plan.color}35`
                    : "none",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.boxShadow = `0 4px 20px ${plan.color}35`;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.boxShadow = plan.popular
                    ? `0 4px 20px ${plan.color}35`
                    : "none";
                }}
              >
                {plan.cta}
              </button>
            </div>
          ))}
        </div>
        <div
          style={{
            textAlign: "center",
            marginTop: 26,
            fontSize: 12,
            color: "rgba(255,255,255,0.25)",
            lineHeight: 1.7,
          }}
        >
          All plans include 95+ threat intelligence feeds, Gemini AI analysis,
          and SOAR integrations.
          <br />
          <span style={{ color: "#22d3a0", cursor: "pointer" }}>
            Contact sales for custom enterprise pricing →
          </span>
        </div>
      </div>
    </div>
  );
}

export default function CipherScan() {
  const [target, setTarget] = useState("");
  const [type, setType] = useState("url");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [cached, setCached] = useState(false);
  const [error, setError] = useState(null);
  const [scanTarget, setScanTarget] = useState("");
  const [scanType, setScanType] = useState("url");
  const [showAPI, setShowAPI] = useState(false);
  const [showPricing, setShowPricing] = useState(false);
  const resultsRef = useRef(null);

  const handleScan = async () => {
    if (!target.trim()) return;
    setScanning(true);
    setResult(null);
    setError(null);
    setScanTarget(target.trim());
    setScanType(type);
    try {
      const json = await callScanAPI(target.trim(), type);
      setResult(json.data);
      setCached(!!json.cached);
      setTimeout(
        () => resultsRef.current?.scrollIntoView({ behavior: "smooth" }),
        100,
      );
    } catch (e) {
      setError(e.message || "Scan failed. Make sure the backend is running.");
    } finally {
      setScanning(false);
    }
  };

  const bannerCfg = result
    ? ({
        green: {
          accent: "#22d3a0",
          bg: "rgba(34,211,160,0.08)",
          border: "rgba(34,211,160,0.25)",
          icon: "🟢",
          badge: "SAFE",
        },
        yellow: {
          accent: "#f5a623",
          bg: "rgba(245,166,35,0.08)",
          border: "rgba(245,166,35,0.25)",
          icon: "🟡",
          badge: "SUSPICIOUS",
        },
        red: {
          accent: "#ff4d6d",
          bg: "rgba(255,77,109,0.08)",
          border: "rgba(255,77,109,0.25)",
          icon: "🔴",
          badge: "DANGER",
        },
      }[result?.vendorVerdict?.color] ?? {
        accent: "#6b7a99",
        bg: "rgba(107,122,153,0.08)",
        border: "rgba(107,122,153,0.2)",
        icon: "⬜",
        badge: "UNKNOWN",
      })
    : null;

  const ai = result?.aiAnalysis;
  const aiColor = ai
    ? ai.riskScore >= 70
      ? "#ff4d6d"
      : ai.riskScore >= 35
        ? "#f5a623"
        : "#22d3a0"
    : "#22d3a0";
  const confMeta = ai?.confidence ? CONFIDENCE_META[ai.confidence] : null;

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;600;700;800&display=swap');
        html,body{overflow-x:hidden;max-width:100vw;width:100%;}
        *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
        body{background:#040b14;color:#e8edf5;font-family:'Syne',sans-serif;min-height:100vh;}
        ::-webkit-scrollbar{width:5px;}
        ::-webkit-scrollbar-track{background:rgba(255,255,255,0.02);}
        ::-webkit-scrollbar-thumb{background:rgba(34,211,160,0.3);border-radius:3px;}
        @keyframes ping{75%,100%{transform:scale(2);opacity:0;}}
        @keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.45;}}
        @keyframes spin{from{transform:rotate(0deg);}to{transform:rotate(360deg);}}
        @keyframes fadeSlideUp{from{opacity:0;transform:translateY(18px);}to{opacity:1;transform:translateY(0);}}
        @keyframes float{0%,100%{transform:translateY(0);}50%{transform:translateY(-9px);}}
        @keyframes gridMove{from{background-position:0 0;}to{background-position:0 40px;}}
        @keyframes slideInRight{from{transform:translateX(100%);}to{transform:translateX(0);}}
        .fu{animation:fadeSlideUp 0.42s ease forwards;}
        .d1{animation-delay:0.06s;opacity:0;}.d2{animation-delay:0.12s;opacity:0;}
        .d3{animation-delay:0.18s;opacity:0;}.d4{animation-delay:0.24s;opacity:0;}
        .d5{animation-delay:0.30s;opacity:0;}
        /* Only apply hover transforms on devices that support hover */
        @media (hover: none) {
          * { -webkit-tap-highlight-color: rgba(34,211,160,0.15); }
        }
        @media(max-width:640px){
          .stats-g{grid-template-columns:repeat(2,1fr)!important;}
          .ai-g{grid-template-columns:1fr!important;}
          .intel-g{grid-template-columns:1fr!important;}
          .eng-g{grid-template-columns:1fr!important;}
          .nav-l{display:none!important;}
          .hero-h{font-size:26px!important;letter-spacing:-1px!important;line-height:1.15!important;}
          .scan-bar{flex-direction:column!important;border-radius:12px!important;padding:8px!important;gap:6px!important;}
          .scan-bar select{border-right:none!important;border-bottom:1px solid rgba(255,255,255,0.08)!important;border-radius:8px!important;padding:10px 14px!important;width:100%!important;}
          .scan-bar input{padding:10px 14px!important;width:100%!important;}
          .scan-bar button{width:100%!important;border-radius:8px!important;padding:12px!important;}
          .result-header{flex-direction:column!important;align-items:flex-start!important;}
          .verdict-banner{flex-direction:column!important;gap:14px!important;}
          .verdict-banner-right{justify-content:flex-start!important;}
          .ai-top-row{flex-direction:column!important;align-items:flex-start!important;}
          .footer-inner{flex-direction:column!important;gap:14px!important;}
          .footer-stats{gap:16px!important;}
          .modal-panel{width:100%!important;max-width:100%!important;height:100%!important;max-height:100%!important;border-radius:0!important;margin:0!important;}
          .modal-tabs{flex-wrap:wrap!important;gap:4px!important;}
          pre,code{word-break:break-all!important;white-space:pre-wrap!important;}
          .loading-target{max-width:220px!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important;}
          .info-row-val{max-width:55%!important;word-break:break-all!important;text-align:right!important;}
          .pricing-grid{grid-template-columns:1fr!important;}
        }
      `}</style>

      <div
        style={{
          position: "fixed",
          inset: 0,
          pointerEvents: "none",
          zIndex: 0,
          background: `radial-gradient(ellipse 80% 50% at 15% 15%,rgba(34,211,160,0.055) 0%,transparent 65%),
        radial-gradient(ellipse 60% 40% at 85% 85%,rgba(0,140,255,0.05) 0%,transparent 65%)`,
        }}
      />
      <div
        style={{
          position: "fixed",
          inset: 0,
          pointerEvents: "none",
          zIndex: 0,
          backgroundImage: `linear-gradient(rgba(34,211,160,0.023) 1px,transparent 1px),linear-gradient(90deg,rgba(34,211,160,0.023) 1px,transparent 1px)`,
          backgroundSize: "40px 40px",
          animation: "gridMove 10s linear infinite",
        }}
      />

      <div
        style={{
          position: "relative",
          zIndex: 1,
          maxWidth: 980,
          margin: "0 auto",
          padding: "0 clamp(12px,4vw,20px) 80px",
        }}
      >
        <header
          style={{
            padding: "30px 0 16px",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div
              style={{
                width: 38,
                height: 38,
                borderRadius: 9,
                background: "linear-gradient(135deg,#22d3a0 0%,#0091ff 100%)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 19,
                boxShadow: "0 0 24px rgba(34,211,160,0.45)",
              }}
            >
              🔐
            </div>
            <div>
              <div
                style={{ fontSize: 19, fontWeight: 800, letterSpacing: -0.5 }}
              >
                Cipher<span style={{ color: "#22d3a0" }}>Scan</span>
              </div>
              <div
                style={{
                  fontFamily: "'Share Tech Mono',monospace",
                  fontSize: 8.5,
                  color: "rgba(255,255,255,0.28)",
                  letterSpacing: 2.5,
                  marginTop: 1,
                }}
              >
                THREAT INTELLIGENCE PLATFORM
              </div>
            </div>
          </div>
          <div
            className="nav-l"
            style={{ display: "flex", gap: 4, alignItems: "center" }}
          >
            <div
              style={{
                width: 1,
                height: 20,
                background: "rgba(255,255,255,0.1)",
                margin: "0 4px",
              }}
            />
            <button
              onClick={() => setShowAPI(true)}
              style={{
                padding: "7px 14px",
                borderRadius: 7,
                fontSize: 12.5,
                color: "#0091ff",
                cursor: "pointer",
                background: "rgba(0,145,255,0.08)",
                border: "1px solid rgba(0,145,255,0.25)",
                transition: "all 0.2s",
                fontFamily: "'Syne',sans-serif",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = "rgba(0,145,255,0.15)";
                e.currentTarget.style.boxShadow =
                  "0 0 12px rgba(0,145,255,0.2)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "rgba(0,145,255,0.08)";
                e.currentTarget.style.boxShadow = "none";
              }}
            >
              ⚡ API
            </button>
            <button
              onClick={() => setShowPricing(true)}
              style={{
                padding: "7px 14px",
                borderRadius: 7,
                fontSize: 12.5,
                color: "#f5a623",
                cursor: "pointer",
                background: "rgba(245,166,35,0.08)",
                border: "1px solid rgba(245,166,35,0.25)",
                transition: "all 0.2s",
                fontFamily: "'Syne',sans-serif",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = "rgba(245,166,35,0.15)";
                e.currentTarget.style.boxShadow =
                  "0 0 12px rgba(245,166,35,0.2)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "rgba(245,166,35,0.08)";
                e.currentTarget.style.boxShadow = "none";
              }}
            >
              💎 Pricing
            </button>
          </div>
        </header>

        <section
          style={{
            padding: "clamp(24px,6vw,52px) 0 clamp(20px,4vw,44px)",
            textAlign: "center",
          }}
        >
          <div
            style={{
              fontSize: 50,
              marginBottom: 16,
              animation: "float 4s ease-in-out infinite",
              display: "inline-block",
              filter: "drop-shadow(0 0 22px rgba(34,211,160,0.3))",
            }}
          >
            🛡️
          </div>
          <h1
            className="hero-h"
            style={{
              fontSize: 50,
              fontWeight: 800,
              letterSpacing: -2,
              lineHeight: 1.08,
              marginBottom: 14,
              color: "#e8edf5",
            }}
          >
            Detect Threats.{" "}
            <span
              style={{
                background: "linear-gradient(120deg,#22d3a0 0%,#00c8ff 100%)",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
              }}
            >
              Stay Secure.
            </span>
          </h1>
          <p
            style={{
              fontSize: 15,
              color: "rgba(255,255,255,0.4)",
              maxWidth: 420,
              margin: "0 auto 34px",
              lineHeight: 1.72,
            }}
          >
            Scan URLs and IPs against VirusTotal, AlienVault OTX, URLHaus,
            Google Safe Browsing and more — with real-time Gemini AI analysis.
          </p>
          <div
            style={{
              display: "flex",
              maxWidth: 640,
              margin: "0 auto",
              background: "rgba(255,255,255,0.04)",
              border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 14,
              padding: 6,
              transition: "box-shadow 0.3s,border-color 0.3s",
              gap: 0,
            }}
            className="scan-bar"
            onFocusCapture={(e) => {
              e.currentTarget.style.boxShadow =
                "0 0 0 3px rgba(34,211,160,0.11),0 0 40px rgba(34,211,160,0.06)";
              e.currentTarget.style.borderColor = "rgba(34,211,160,0.28)";
            }}
            onBlurCapture={(e) => {
              e.currentTarget.style.boxShadow = "none";
              e.currentTarget.style.borderColor = "rgba(255,255,255,0.1)";
            }}
          >
            <select
              value={type}
              onChange={(e) => setType(e.target.value)}
              style={{
                background: "rgba(34,211,160,0.09)",
                border: "none",
                borderRight: "1px solid rgba(255,255,255,0.08)",
                borderRadius: "8px 0 0 8px",
                padding: "0 14px",
                color: "#22d3a0",
                fontSize: 12.5,
                fontWeight: 700,
                cursor: "pointer",
                outline: "none",
                fontFamily: "'Share Tech Mono',monospace",
                flexShrink: 0,
              }}
            >
              <option value="url" style={{ background: "#0d1a2a" }}>
                URL
              </option>
              <option value="ip" style={{ background: "#0d1a2a" }}>
                IP
              </option>
            </select>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              placeholder="Enter URL or IP…"
              disabled={scanning}
              style={{
                flex: 1,
                minWidth: 0,
                background: "none",
                border: "none",
                outline: "none",
                padding: "14px 16px",
                color: "#e8edf5",
                fontSize: 14.5,
                fontFamily: "'Syne',sans-serif",
              }}
            />
            <button
              onClick={handleScan}
              disabled={scanning || !target.trim()}
              style={{
                background:
                  scanning || !target.trim()
                    ? "rgba(34,211,160,0.14)"
                    : "linear-gradient(135deg,#22d3a0,#00c08a)",
                border: "none",
                borderRadius: "8px",
                padding: "12px 26px",
                color:
                  scanning || !target.trim()
                    ? "rgba(255,255,255,0.32)"
                    : "#04120d",
                fontSize: 13.5,
                fontWeight: 700,
                cursor: scanning || !target.trim() ? "not-allowed" : "pointer",
                transition: "all 0.2s",
                fontFamily: "'Syne',sans-serif",
                whiteSpace: "nowrap",
                boxShadow:
                  !scanning && target.trim()
                    ? "0 0 24px rgba(34,211,160,0.38)"
                    : "none",
              }}
            >
              {scanning ? "Scanning…" : "Scan Now"}
            </button>
          </div>
        </section>

        {scanning && (
          <div
            style={{
              background: "rgba(255,255,255,0.02)",
              border: "1px solid rgba(255,255,255,0.06)",
              borderRadius: 16,
              marginBottom: 32,
            }}
          >
            <Loading target={scanTarget} />
          </div>
        )}

        {error && (
          <div
            style={{
              background: "rgba(255,77,109,0.07)",
              border: "1px solid rgba(255,77,109,0.22)",
              borderRadius: 12,
              padding: "16px 20px",
              marginBottom: 32,
            }}
          >
            <div
              style={{
                color: "#ff4d6d",
                fontSize: 14,
                fontWeight: 600,
                marginBottom: 4,
              }}
            >
              ⚠ Scan Error
            </div>
            <div style={{ color: "rgba(255,255,255,0.55)", fontSize: 13 }}>
              {error}
            </div>
          </div>
        )}

        {result && !scanning && (
          <div
            ref={resultsRef}
            style={{ display: "flex", flexDirection: "column", gap: 26 }}
          >
            <div
              className="fu result-header"
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                flexWrap: "wrap",
                gap: 8,
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  flexWrap: "wrap",
                }}
              >
                <div
                  style={{
                    fontFamily: "'Share Tech Mono',monospace",
                    fontSize: 11,
                    color: "rgba(255,255,255,0.28)",
                  }}
                >
                  SCAN COMPLETE ·{" "}
                  <span style={{ color: "#22d3a0" }}>{scanTarget}</span> ·{" "}
                  {new Date().toLocaleTimeString()}
                </div>
                {cached && (
                  <div
                    style={{
                      fontFamily: "'Share Tech Mono',monospace",
                      fontSize: 10,
                      color: "#0091ff",
                      background: "rgba(0,145,255,0.1)",
                      border: "1px solid rgba(0,145,255,0.25)",
                      borderRadius: 4,
                      padding: "2px 9px",
                      letterSpacing: 1,
                    }}
                  >
                    📦 CACHED
                  </div>
                )}
              </div>
              <button
                onClick={() => {
                  setResult(null);
                  setTarget("");
                  setScanTarget("");
                }}
                style={{
                  background: "none",
                  border: "1px solid rgba(255,255,255,0.1)",
                  borderRadius: 6,
                  padding: "6px 14px",
                  color: "rgba(255,255,255,0.4)",
                  fontSize: 12,
                  cursor: "pointer",
                  transition: "all 0.2s",
                  fontFamily: "'Share Tech Mono',monospace",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.borderColor = "rgba(34,211,160,0.28)";
                  e.currentTarget.style.color = "#22d3a0";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.borderColor = "rgba(255,255,255,0.1)";
                  e.currentTarget.style.color = "rgba(255,255,255,0.4)";
                }}
              >
                ↩ New Scan
              </button>
            </div>

            <div
              className="fu d1 verdict-banner"
              style={{
                background: bannerCfg.bg,
                border: `1px solid ${bannerCfg.border}`,
                borderLeft: `4px solid ${bannerCfg.accent}`,
                borderRadius: 13,
                padding: "20px 26px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                flexWrap: "wrap",
                gap: 14,
                boxShadow: `0 0 40px ${bannerCfg.bg}`,
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                <span style={{ fontSize: 28 }}>{bannerCfg.icon}</span>
                <div>
                  <div
                    style={{
                      fontFamily: "'Share Tech Mono',monospace",
                      fontSize: 9.5,
                      color: "rgba(255,255,255,0.32)",
                      letterSpacing: 3,
                      marginBottom: 4,
                    }}
                  >
                    VENDOR VERDICT
                  </div>
                  <div style={{ fontSize: 18, fontWeight: 700, color: "#fff" }}>
                    <span
                      style={{
                        color: bannerCfg.accent,
                        fontSize: 22,
                        fontFamily: "'Share Tech Mono',monospace",
                      }}
                    >
                      {result.vendorVerdict?.flagged}
                    </span>
                    <span style={{ color: "rgba(255,255,255,0.32)" }}>
                      {" "}
                      / {result.vendorVerdict?.total}{" "}
                    </span>
                    vendors flagged this target
                  </div>
                  {result.vendorVerdict?.percentage != null && (
                    <div
                      style={{
                        fontSize: 12,
                        color: "rgba(255,255,255,0.32)",
                        marginTop: 2,
                        fontFamily: "'Share Tech Mono',monospace",
                      }}
                    >
                      {result.vendorVerdict.percentage}% detection rate
                    </div>
                  )}
                </div>
              </div>
              <div
                style={{
                  padding: "7px 20px",
                  background: bannerCfg.bg,
                  border: `1px solid ${bannerCfg.border}`,
                  borderRadius: 100,
                  fontFamily: "'Share Tech Mono',monospace",
                  fontSize: 12.5,
                  fontWeight: 700,
                  color: bannerCfg.accent,
                  letterSpacing: 2.5,
                }}
              >
                {bannerCfg.badge}
              </div>
            </div>

            <div className="fu d2">
              <SLabel sub="Aggregated VirusTotal verdict counts across all engines">
                Detection Statistics
              </SLabel>
              <div
                className="stats-g"
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(4,1fr)",
                  gap: 12,
                }}
              >
                {[
                  {
                    key: "malicious",
                    label: "Malicious",
                    icon: "☠",
                    color: "#ff4d6d",
                  },
                  {
                    key: "suspicious",
                    label: "Suspicious",
                    icon: "⚠",
                    color: "#f5a623",
                  },
                  {
                    key: "harmless",
                    label: "Harmless",
                    icon: "✓",
                    color: "#22d3a0",
                  },
                  {
                    key: "undetected",
                    label: "Undetected",
                    icon: "◌",
                    color: "#6b7a99",
                  },
                ].map((c) => (
                  <div
                    key={c.key}
                    style={{
                      background: "rgba(255,255,255,0.03)",
                      border: "1px solid rgba(255,255,255,0.06)",
                      borderRadius: 12,
                      padding: "18px 12px",
                      textAlign: "center",
                      cursor: "default",
                      transition: "all 0.2s",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.transform = "translateY(-3px)";
                      e.currentTarget.style.boxShadow = `0 8px 28px ${c.color}16`;
                      e.currentTarget.style.borderColor = `${c.color}22`;
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.transform = "none";
                      e.currentTarget.style.boxShadow = "none";
                      e.currentTarget.style.borderColor =
                        "rgba(255,255,255,0.06)";
                    }}
                  >
                    <div style={{ fontSize: 22, marginBottom: 7 }}>
                      {c.icon}
                    </div>
                    <div
                      style={{
                        fontSize: 32,
                        fontWeight: 800,
                        fontFamily: "'Share Tech Mono',monospace",
                        color: c.color,
                        textShadow: `0 0 22px ${c.color}50`,
                      }}
                    >
                      {result.stats?.[c.key] ?? 0}
                    </div>
                    <div
                      style={{
                        fontSize: 10,
                        color: "rgba(255,255,255,0.32)",
                        marginTop: 4,
                        letterSpacing: 1.2,
                        textTransform: "uppercase",
                      }}
                    >
                      {c.label}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {ai && (
              <div className="fu d3">
                <SLabel
                  sub="Powered by Google Gemini — real-time AI threat assessment"
                  right={
                    confMeta && (
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 6,
                          fontFamily: "'Share Tech Mono',monospace",
                          fontSize: 10.5,
                          color: confMeta.color,
                          background: `${confMeta.color}12`,
                          border: `1px solid ${confMeta.color}30`,
                          borderRadius: 6,
                          padding: "4px 10px",
                          letterSpacing: 0.5,
                        }}
                      >
                        <span>{confMeta.icon}</span> {confMeta.label}
                      </div>
                    )
                  }
                >
                  AI Intelligence Analysis
                </SLabel>
                <div
                  className="ai-g"
                  style={{
                    background: "rgba(255,255,255,0.025)",
                    border: "1px solid rgba(255,255,255,0.07)",
                    borderRadius: 16,
                    padding: 26,
                    display: "grid",
                    gridTemplateColumns: "148px 1fr",
                    gap: 28,
                    alignItems: "start",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      alignItems: "center",
                      gap: 10,
                    }}
                  >
                    <RiskArc score={ai.riskScore} />
                    <div
                      style={{
                        fontFamily: "'Share Tech Mono',monospace",
                        fontSize: 9.5,
                        letterSpacing: 2,
                        color: aiColor,
                        textTransform: "uppercase",
                        padding: "3px 11px",
                        border: `1px solid ${aiColor}40`,
                        borderRadius: 4,
                        background: `${aiColor}10`,
                      }}
                    >
                      {ai.threatCategory}
                    </div>
                  </div>
                  <div
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: 20,
                    }}
                  >
                    <div>
                      <div
                        style={{
                          fontFamily: "'Share Tech Mono',monospace",
                          fontSize: 9,
                          color: "#22d3a0",
                          letterSpacing: 3,
                          marginBottom: 8,
                        }}
                      >
                        ✦ AI SUMMARY
                      </div>
                      <p
                        style={{
                          fontSize: 13.5,
                          lineHeight: 1.8,
                          color: "rgba(255,255,255,0.66)",
                          margin: 0,
                        }}
                      >
                        {ai.summary}
                      </p>
                    </div>
                    {ai.keyInsights?.length > 0 && (
                      <div>
                        <div
                          style={{
                            fontFamily: "'Share Tech Mono',monospace",
                            fontSize: 9,
                            color: "#0091ff",
                            letterSpacing: 3,
                            marginBottom: 8,
                          }}
                        >
                          ◈ KEY INSIGHTS
                        </div>
                        <ul
                          style={{
                            listStyle: "none",
                            padding: 0,
                            margin: 0,
                            display: "flex",
                            flexDirection: "column",
                            gap: 7,
                          }}
                        >
                          {ai.keyInsights.map((ins, i) => (
                            <li
                              key={i}
                              style={{
                                display: "flex",
                                gap: 9,
                                alignItems: "flex-start",
                                background: "rgba(0,145,255,0.05)",
                                border: "1px solid rgba(0,145,255,0.1)",
                                borderRadius: 7,
                                padding: "8px 12px",
                              }}
                            >
                              <span
                                style={{
                                  color: "#0091ff",
                                  marginTop: 1,
                                  flexShrink: 0,
                                  fontSize: 12,
                                }}
                              >
                                ◈
                              </span>
                              <span
                                style={{
                                  fontSize: 13,
                                  color: "rgba(255,255,255,0.62)",
                                  lineHeight: 1.55,
                                }}
                              >
                                {ins}
                              </span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {ai.recommendations?.length > 0 && (
                      <div>
                        <div
                          style={{
                            fontFamily: "'Share Tech Mono',monospace",
                            fontSize: 9,
                            color: "rgba(255,255,255,0.28)",
                            letterSpacing: 3,
                            marginBottom: 8,
                          }}
                        >
                          RECOMMENDATIONS
                        </div>
                        <ul
                          style={{
                            listStyle: "none",
                            padding: 0,
                            margin: 0,
                            display: "flex",
                            flexDirection: "column",
                            gap: 7,
                          }}
                        >
                          {ai.recommendations.map((rec, i) => (
                            <li
                              key={i}
                              style={{
                                display: "flex",
                                gap: 9,
                                alignItems: "flex-start",
                              }}
                            >
                              <span
                                style={{
                                  color: aiColor,
                                  marginTop: 2,
                                  flexShrink: 0,
                                  fontSize: 14,
                                }}
                              >
                                ›
                              </span>
                              <span
                                style={{
                                  fontSize: 13,
                                  color: "rgba(255,255,255,0.6)",
                                  lineHeight: 1.55,
                                }}
                              >
                                {rec}
                              </span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {result.engineResults?.length > 0 && (
              <div className="fu d4">
                <SLabel
                  sub={`${result.engineResults.length} engines queried — set depends on scan type (URL vs IP)`}
                >
                  Security Engine Results
                </SLabel>
                <div
                  className="eng-g"
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fill,minmax(218px,1fr))",
                    gap: 10,
                  }}
                >
                  {result.engineResults.map(({ engine, verdict }, i) => {
                    const v = VERDICT_META[verdict] || VERDICT_META.unknown;
                    return (
                      <div
                        key={i}
                        style={{
                          background: "rgba(255,255,255,0.03)",
                          border: "1px solid rgba(255,255,255,0.07)",
                          borderRadius: 10,
                          padding: "13px 15px",
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          cursor: "default",
                          transition: "all 0.2s",
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.background = v.bg;
                          e.currentTarget.style.borderColor = `${v.color}40`;
                          e.currentTarget.style.transform = "translateY(-2px)";
                          e.currentTarget.style.boxShadow = v.glow;
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.background =
                            "rgba(255,255,255,0.03)";
                          e.currentTarget.style.borderColor =
                            "rgba(255,255,255,0.07)";
                          e.currentTarget.style.transform = "none";
                          e.currentTarget.style.boxShadow = "none";
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 9,
                          }}
                        >
                          <span style={{ fontSize: 16 }}>
                            {ENGINE_ICONS[engine] || "🔒"}
                          </span>
                          <span
                            style={{
                              fontSize: 13,
                              color: "rgba(255,255,255,0.78)",
                              fontWeight: 600,
                            }}
                          >
                            {engine}
                          </span>
                        </div>
                        <div
                          style={{
                            fontSize: 10,
                            fontWeight: 700,
                            color: v.color,
                            background: v.bg,
                            border: `1px solid ${v.color}40`,
                            borderRadius: 100,
                            padding: "2px 9px",
                            letterSpacing: 0.5,
                            fontFamily: "'Share Tech Mono',monospace",
                          }}
                        >
                          {v.label}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            <div className="fu d5">
              <SLabel sub="Resolved IP, geolocation, scan attributes, and VirusTotal flagging vendors">
                Target Intelligence
              </SLabel>
              <div className="intel-g">
                <TargetIntel
                  data={result}
                  scanTarget={scanTarget}
                  scanType={scanType}
                />
              </div>
            </div>
          </div>
        )}

        {!scanning && !result && !error && (
          <div
            style={{
              textAlign: "center",
              padding: "0 0 40px",
              color: "rgba(255,255,255,0.12)",
            }}
          >
            <div style={{ fontSize: 36, marginBottom: 10 }}>🔍</div>
            <div
              style={{
                fontFamily: "'Share Tech Mono',monospace",
                fontSize: 11,
                letterSpacing: 3,
              }}
            >
              AWAITING TARGET
            </div>
          </div>
        )}

        <footer
          style={{
            marginTop: 70,
            paddingTop: 26,
            borderTop: "1px solid rgba(255,255,255,0.05)",
            display: "flex",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: 14,
            alignItems: "center",
          }}
          className="footer-inner"
        >
          <div
            className="footer-stats"
            style={{ display: "flex", gap: 32, flexWrap: "wrap" }}
          >
            {[
              { label: "Engines", value: "7+" },
              { label: "AI Model", value: "Gemini" },
              { label: "Cache", value: "MongoDB" },
              { label: "Version", value: "v1.0.0" },
            ].map((s) => (
              <div key={s.label}>
                <div
                  style={{
                    fontFamily: "'Share Tech Mono',monospace",
                    fontSize: 16,
                    fontWeight: 700,
                    color: "#22d3a0",
                  }}
                >
                  {s.value}
                </div>
                <div
                  style={{
                    fontSize: 10,
                    color: "rgba(255,255,255,0.22)",
                    letterSpacing: 1.2,
                    textTransform: "uppercase",
                    marginTop: 2,
                  }}
                >
                  {s.label}
                </div>
              </div>
            ))}
          </div>
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <button
              onClick={() => setShowAPI(true)}
              style={{
                background: "none",
                border: "1px solid rgba(0,145,255,0.22)",
                borderRadius: 6,
                padding: "6px 13px",
                color: "#0091ff",
                fontSize: 11.5,
                cursor: "pointer",
                fontFamily: "'Share Tech Mono',monospace",
                transition: "all 0.2s",
              }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.background = "rgba(0,145,255,0.08)")
              }
              onMouseLeave={(e) => (e.currentTarget.style.background = "none")}
            >
              API Docs
            </button>
            <button
              onClick={() => setShowPricing(true)}
              style={{
                background: "none",
                border: "1px solid rgba(245,166,35,0.22)",
                borderRadius: 6,
                padding: "6px 13px",
                color: "#f5a623",
                fontSize: 11.5,
                cursor: "pointer",
                fontFamily: "'Share Tech Mono',monospace",
                transition: "all 0.2s",
              }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.background = "rgba(245,166,35,0.08)")
              }
              onMouseLeave={(e) => (e.currentTarget.style.background = "none")}
            >
              Pricing
            </button>
            <span
              style={{
                fontSize: 11,
                color: "rgba(255,255,255,0.16)",
                fontFamily: "'Share Tech Mono',monospace",
              }}
            >
              © 2026 CipherScan
            </span>
          </div>
        </footer>
      </div>

      {showAPI && <APIModal onClose={() => setShowAPI(false)} />}
      {showPricing && <PricingModal onClose={() => setShowPricing(false)} />}
    </>
  );
}
