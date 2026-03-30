export const scanPhishTank = async (target) => {
  try {
    return {
      engine: "PhishTank",
      verdict: "unknown",
    };
  } catch (err) {
    return {
      engine: "PhishTank",
      verdict: "unknown",
    };
  }
};
