import { analyzeWithGemini } from "./providers/gemini.js";

export const analyzeScan = async (data = {}) => {
  const {
    stats = {},
    vendorVerdict = {},
    vendors = {},
    engineResults = [],
  } = data;

  const hasConflict =
    engineResults?.some((e) => e.verdict === "malicious") &&
    engineResults?.some((e) => e.verdict === "clean");

  const maliciousEngines = engineResults
    ?.filter((e) => e.verdict === "malicious")
    .map((e) => e.engine);

  const totalEngines = engineResults?.length || 0;

  const malicious = stats?.malicious || 0;
  const suspicious = stats?.suspicious || 0;
  const harmless = stats?.harmless || 0;
  const undetected = stats?.undetected || 0;
  const total = malicious + suspicious + harmless + undetected || 1;

  let riskScore = Math.round(
    ((malicious * 1.0 + suspicious * 0.6) / total) * 100,
  );
  if (hasConflict) riskScore += 10;
  if (malicious > 0) riskScore += 15;
  if (riskScore > 100) riskScore = 100;

  let threatCategory = "safe";
  if (riskScore > 80) threatCategory = "malicious";
  else if (riskScore > 50) threatCategory = "suspicious";
  else if (riskScore > 20) threatCategory = "unknown";

  let confidence = "high";
  if (undetected > total * 0.5) confidence = "low";
  else if (hasConflict) confidence = "medium";

  const prompt = `
You are CipherScan AI — an advanced cybersecurity threat analyst powered by threat intelligence LLM.

Analyze the following scan data and return a professional, detailed security assessment like a real SOC analyst.

=== SCAN DATA ===

Stats:
- Malicious engines (VirusTotal): ${malicious}
- Suspicious engines (VirusTotal): ${suspicious}  
- Harmless engines (VirusTotal): ${harmless}
- Undetected engines (VirusTotal): ${undetected}
- Total Engines scanned: ${harmless + undetected + malicious + suspicious}

Custom Engine Results (${totalEngines} engines):
${engineResults?.map((e) => `- ${e.engine}: ${e.verdict}`).join("\n") || "None"}

Conflict Detected: ${hasConflict ? "YES — some engines say malicious, others say clean" : "NO"}
Pre-calculated Risk Score: ${riskScore}/100
Threat Category: ${threatCategory}
Confidence: ${confidence}

Malicious Custom Engines: ${maliciousEngines?.length ? maliciousEngines.join(", ") : "None"}

Vendor Verdict (VirusTotal):
- ${vendorVerdict?.flagged || 0} out of ${vendorVerdict?.total || 0} vendors flagged this (${vendorVerdict?.percentage || 0}%)

Flagged Vendors: ${vendors?.names?.join(", ") || "None"}

=== INSTRUCTIONS ===

Write like a real senior cybersecurity analyst from a SOC team. Be specific and technical.

- Analyze ALL engine results holistically (both custom engines AND VirusTotal stats)
- If malicious engines flagged it, explain what threat type it could be (C2, phishing, malware loader, info-stealer, botnet, etc.)
- If conflict exists between engines, explain WHY they might disagree (false positive, outdated signatures, different detection methods)
- Reference known threat families or attack patterns if the data matches
- Mention specific engine names in your analysis
- Be direct, professional, and actionable
- If safe, still explain why it's trustworthy with the data

Return STRICT JSON only. No markdown. No backticks. No explanation outside JSON:
{
  "summary": "3-4 sentence expert analysis. Be specific about threat type, mention engine names, explain the risk clearly based on ALL the data provided.",
  "keyInsights": [
    "Specific insight with technical detail mentioning engine names or stats",
    "Insight about what the VirusTotal vendor data shows",
    "Insight about conflict or agreement between engines",
    "Insight about confidence level and what undetected engines mean"
  ],
  "recommendations": [
    "Specific actionable recommendation 1",
    "Specific actionable recommendation 2",
    "Specific actionable recommendation 3"
  ]
}
`;

  try {
    const geminiRawResponse = await analyzeWithGemini(prompt);

    let parsed;
    try {
      if (typeof geminiRawResponse === "object" && geminiRawResponse !== null) {
        parsed = geminiRawResponse;
      } else if (typeof geminiRawResponse === "string") {
        const cleaned = geminiRawResponse
          .replace(/```json/gi, "")
          .replace(/```/g, "")
          .trim();
        parsed = JSON.parse(cleaned);
      } else {
        throw new Error("Unexpected Gemini response type");
      }
    } catch (parseErr) {
      console.error(" Gemini parse failed:", parseErr.message);
      throw new Error("Gemini parse failed");
    }

    return {
      riskScore,
      threatCategory,
      confidence,
      summary:
        parsed?.summary ||
        buildFallbackSummary(
          hasConflict,
          malicious,
          harmless,
          undetected,
          maliciousEngines,
          totalEngines,
        ),
      keyInsights:
        Array.isArray(parsed?.keyInsights) && parsed.keyInsights.length > 0
          ? parsed.keyInsights
          : buildFallbackInsights(
              hasConflict,
              malicious,
              harmless,
              undetected,
              suspicious,
              maliciousEngines,
              totalEngines,
            ),
      recommendations:
        Array.isArray(parsed?.recommendations) &&
        parsed.recommendations.length > 0
          ? parsed.recommendations
          : buildFallbackRecommendations(threatCategory),
    };
  } catch (err) {
    console.error("Gemini failed, using smart fallback:", err.message);

    return {
      riskScore,
      threatCategory,
      confidence,
      summary: buildFallbackSummary(
        hasConflict,
        malicious,
        harmless,
        undetected,
        maliciousEngines,
        totalEngines,
      ),
      keyInsights: buildFallbackInsights(
        hasConflict,
        malicious,
        harmless,
        undetected,
        suspicious,
        maliciousEngines,
        totalEngines,
      ),
      recommendations: buildFallbackRecommendations(threatCategory),
    };
  }
};

const buildFallbackSummary = (
  hasConflict,
  malicious,
  harmless,
  undetected,
  maliciousEngines,
  totalEngines,
) => {
  if (hasConflict) {
    return `Conflicting signals detected across ${totalEngines} custom engines. ${maliciousEngines.join(", ")} flagged this target as malicious, while ${harmless > 0 ? harmless + " VirusTotal engines" : "other engines"} report it as clean. This disagreement may indicate a false positive, an obfuscated payload, or a newly identified threat not yet in all signature databases. Exercise caution until further verification.`;
  }

  if (malicious > 0) {
    return `${maliciousEngines.join(", ")} flagged this target as malicious out of ${totalEngines} engines scanned. VirusTotal reports ${malicious} malicious detection(s) with ${harmless} engines marking it harmless. The presence of malicious flags warrants immediate caution and further investigation.`;
  }

  const totalScanned = harmless + undetected;
  return `This target appears largely safe based on available scan data. ${harmless} out of ${totalScanned} VirusTotal engines report it as harmless, with no malicious detections recorded. ${undetected > 0 ? `${undetected} engines returned unrated results, introducing minor uncertainty into the overall confidence.` : "All scanned engines returned clean results."}`;
};

const buildFallbackInsights = (
  hasConflict,
  malicious,
  harmless,
  undetected,
  suspicious,
  maliciousEngines,
  totalEngines,
) => {
  const insights = [];

  if (hasConflict) {
    insights.push(
      `Engine conflict detected: ${maliciousEngines.join(", ")} report malicious while other engines report clean — possible false positive or evasive threat`,
    );
  }

  if (malicious > 0) {
    insights.push(
      `${malicious} VirusTotal engine(s) confirmed malicious activity — high confidence threat signal`,
    );
  }

  if (maliciousEngines.length > 0) {
    insights.push(
      `Custom engines flagged: ${maliciousEngines.join(", ")} — these are reputable threat intelligence feeds`,
    );
  }

  if (harmless > 0) {
    insights.push(
      `${harmless} VirusTotal engines report harmless — majority consensus leans safe`,
    );
  }

  if (suspicious > 0) {
    insights.push(
      `${suspicious} engine(s) returned suspicious verdict — borderline threat indicators present`,
    );
  }

  if (undetected > 0) {
    insights.push(
      `${undetected} engines returned unrated/undetected — incomplete coverage may mask emerging threats`,
    );
  }

  if (insights.length === 0) {
    insights.push(
      `All ${totalEngines} scanned engines returned clean results — target appears safe`,
    );
  }

  return insights;
};

const buildFallbackRecommendations = (threatCategory) => {
  if (threatCategory === "malicious") {
    return [
      "Do not visit or interact with this target under any circumstances",
      "Block this URL/IP at the firewall and DNS level immediately",
      "Run a full endpoint security scan if you have previously accessed this target",
      "Report this target to your security team for further forensic investigation",
    ];
  }

  if (threatCategory === "suspicious") {
    return [
      "Avoid interacting with this target until further analysis is complete",
      "Open in a sandboxed or isolated environment if access is required",
      "Re-scan after 24 hours as threat intelligence databases update frequently",
      "Cross-reference with additional threat feeds like Shodan or AbuseIPDB",
    ];
  }

  if (threatCategory === "unknown") {
    return [
      "Proceed with caution — limited intelligence available for this target",
      "Re-scan periodically to catch any newly added threat signatures",
      "Use additional security tools like URLScan.io for deeper analysis",
    ];
  }

  return [
    "Target appears safe based on current intelligence — normal interaction is acceptable",
    "Re-scan periodically as threat databases update continuously",
    "Monitor for any behavioral anomalies if this is a recurring target",
  ];
};
