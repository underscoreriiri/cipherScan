import { scanURL } from "./virustotal.js";
import { scanOTX } from "./providers/otx.js";
import { scanURLHaus } from "./providers/urlhaus.js";
import { scanGoogleSafe } from "./providers/googleSafeBrowsing.js";
import { scanPhishTank } from "./providers/phishtank.js";
import { scanAbuseIPDB } from "./providers/abuseipdb.js";
import { scanSpamhaus } from "./providers/spamhaus.js";

export const runScan = async (target, type) => {
  if (type === "url") {
    const vt = await scanURL(target);
    const otx = await scanOTX(target, type);
    const urlhaus = await scanURLHaus(target);
    const google = await scanGoogleSafe(target);
    const phish = await scanPhishTank(target);

    const engineResults = [
      {
        engine: "VirusTotal",
        verdict: vt.stats.malicious > 0 ? "malicious" : "clean",
      },
      otx,
      urlhaus,
      google,
      phish,
    ];

    return {
      ...vt,
      engineResults,
    };
  }

  if (type === "ip") {
    const vt = await scanURL(target);
    const otx = await scanOTX(target, type);
    const abuse = await scanAbuseIPDB(target);
    const spamhaus = await scanSpamhaus(target);

    const engineResults = [
      {
        engine: "VirusTotal",
        verdict: vt.stats.malicious > 0 ? "malicious" : "clean",
      },
      otx,
      abuse,
      spamhaus,
    ];

    return {
      ...vt,
      engineResults,
    };
  }

  throw new Error("Invalid scan type");
};
