import axios from "axios";

export const scanGoogleSafe = async (url) => {
  try {
    const res = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_API_KEY}`,
      {
        client: {
          clientId: "cipherScan",
          clientVersion: "1.0.0",
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      },
    );

    const matches = res.data.matches || [];

    return {
      engine: "Google Safe Browsing",
      verdict: matches.length > 0 ? "malicious" : "clean",
    };
  } catch (err) {
    console.error("Google Safe error:", err.message);

    return {
      engine: "Google Safe Browsing",
      verdict: "unknown",
    };
  }
};
