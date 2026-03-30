import axios from "axios";

export const scanAbuseIPDB = async (ip) => {
  try {
    const res = await axios.get(`https://api.abuseipdb.com/api/v2/check`, {
      params: {
        ipAddress: ip,
        maxAgeInDays: 90,
      },
      headers: {
        Key: process.env.ABUSEIPDB_API_KEY,
        Accept: "application/json",
      },
    });

    const score = res.data.data.abuseConfidenceScore;

    let verdict = "clean";

    if (score > 75) verdict = "malicious";
    else if (score > 25) verdict = "suspicious";

    return {
      engine: "AbuseIPDB",
      verdict,
    };
  } catch (err) {
    console.error("AbuseIPDB error:", err.message);

    return {
      engine: "AbuseIPDB",
      verdict: "unknown",
    };
  }
};
