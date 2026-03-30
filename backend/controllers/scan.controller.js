import Scan from "../models/scan.model.js";
import { runScan } from "../services/scan.service.js";
import { analyzeScan } from "../services/ai.service.js";
import { getVendorVerdict } from "../utils/vendorScore.js";
import dns from "dns/promises";

export const scanTarget = async (req, res) => {
  try {
    const { target, type } = req.body;

    if (!target) {
      return res.status(400).json({ error: "Target is required" });
    }

    const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(target);

    if (isIP && type === "url") {
      return res.status(400).json({
        error: "Please Enter a Valid URL",
      });
    }
    if (!isIP && type === "ip") {
      return res.status(400).json({
        error: "Please Enter a Valid IP",
      });
    }

    let finalType = type;
    if (isIP) {
      finalType = "ip";
    }

    const existing = await Scan.findOne({ target, type: finalType });
    if (existing) {
      return res.json({ success: true, cached: true, data: existing });
    }

    const scanResult = await runScan(target, finalType);

    const vendorVerdict = getVendorVerdict(scanResult.stats);

    const results = scanResult.rawReport?.data?.attributes?.results || {};
    const maliciousVendors = Object.values(results)
      .filter((r) => r.category === "malicious")
      .map((r) => r.engine_name);

    const vendors = {
      count: maliciousVendors.length,
      names: maliciousVendors,
    };

    let resolvedIP = null;

    try {
      if (finalType === "url") {
        const host = new URL(target).hostname;
        const ipData = await dns.lookup(host);
        resolvedIP = ipData.address;
      }

      if (finalType === "ip") {
        resolvedIP = target;
      }
    } catch (err) {
      console.error("IP resolve error:", err.message);
    }

    let country = scanResult.rawReport?.data?.attributes?.country || null;

    if (!country && resolvedIP) {
      try {
        const geoRes = await fetch(`http://ip-api.com/json/${resolvedIP}`);
        const geoData = await geoRes.json();
        country = geoData.country || "Unknown";
      } catch (err) {
        country = "Unknown";
      }
    }

    const scan = await Scan.create({
      target,
      type: finalType,
      stats: scanResult.stats,
      attributes: scanResult.attributes,
      rawReport: scanResult.rawReport,
      vendorVerdict,
      engineResults: scanResult.engineResults,
      vendors,
      geo: { country: country || "Unknown" },
      resolvedIP,
    });

    const aiResult = await analyzeScan({
      stats: scanResult.stats,
      vendorVerdict,
      vendors,
      engineResults: scanResult.engineResults,
    });

    scan.aiAnalysis = aiResult;
    await scan.save();

    res.status(201).json({
      success: true,
      cached: false,
      data: scan,
    });
  } catch (err) {
    console.error("Controller Error:", err);
    res.status(500).json({
      error: "Something went wrong",
    });
  }
};
