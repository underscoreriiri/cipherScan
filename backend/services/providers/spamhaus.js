import dns from "dns/promises";

export const scanSpamhaus = async (ip) => {
  try {
    const reversedIP = ip.split(".").reverse().join(".");
    const query = `${reversedIP}.zen.spamhaus.org`;

    await dns.resolve(query);

    return {
      engine: "Spamhaus",
      verdict: "malicious",
    };
  } catch (err) {
    return {
      engine: "Spamhaus",
      verdict: "clean",
    };
  }
};
