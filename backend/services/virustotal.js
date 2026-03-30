import axios from "axios";

const BASE_URL = "https://www.virustotal.com/api/v3";

const vt = axios.create({
  baseURL: BASE_URL,
  headers: {
    "x-apikey": process.env.VIRUSTOTAL_API_KEY,
  },
});

export const scanURL = async (url) => {
  try {
    const params = new URLSearchParams({ url });
    const submit = await vt.post("/urls", params);

    const analysisId = submit.data.data.id;

    return await pollAnalysis(analysisId);
  } catch (err) {
    console.error("VirusTotal Error:", err.response?.data || err.message);
    throw new Error("VirusTotal request failed");
  }
};

const pollAnalysis = async (analysisId) => {
  const MAX_RETRIES = 15;
  const DELAY = 4000;

  for (let i = 0; i < MAX_RETRIES; i++) {
    const res = await vt.get(`/analyses/${analysisId}`);
    const data = res.data.data;
    const status = data.attributes.status;

    if (status === "completed") {
      const stats = data.attributes.stats || {};

      return {
        stats: {
          malicious: stats.malicious || 0,
          harmless: stats.harmless || 0,
          suspicious: stats.suspicious || 0,
          undetected: stats.undetected || 0,
        },
        attributes: {
          lastAnalysisDate: data.attributes.date
            ? new Date(data.attributes.date * 1000)
            : null,
        },
        rawReport: res.data,
      };
    }

    await new Promise((resolve) => setTimeout(resolve, DELAY));
  }

  throw new Error("VirusTotal analysis timeout — try again later");
};
