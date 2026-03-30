import axios from "axios";

export const scanURLHaus = async (target) => {
  try {
    const params = new URLSearchParams();
    params.append("url", target);

    const res = await axios.post(
      "https://urlhaus-api.abuse.ch/v1/url/",
      params,
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "cipherScan-app",
        },
      },
    );

    const data = res.data;

    if (data.query_status === "ok") {
      return {
        engine: "URLHaus",
        verdict: "malicious",
      };
    }

    return {
      engine: "URLHaus",
      verdict: "clean",
    };
  } catch (err) {
    console.error("URLHaus error:", err.response?.data || err.message);

    return {
      engine: "URLHaus",
      verdict: "unknown",
    };
  }
};
