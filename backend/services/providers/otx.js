import axios from "axios";

export const scanOTX = async (target, type) => {
  try {
    let url = "";

    if (type === "url") {
      url = `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(target)}/general`;
    } else if (type === "ip") {
      url = `https://otx.alienvault.com/api/v1/indicators/IPv4/${target}/general`;
    }

    const res = await axios.get(url);

    const pulses = res.data.pulse_info?.count || 0;

    return {
      engine: "AlienVault OTX",
      verdict: pulses > 0 ? "malicious" : "clean",
    };
  } catch (err) {
    console.error("OTX error:", err.message);

    return {
      engine: "AlienVault OTX",
      verdict: "unknown",
    };
  }
};
