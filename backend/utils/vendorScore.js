export const getVendorVerdict = (stats) => {
  const total =
    stats.malicious + stats.harmless + stats.suspicious + stats.undetected || 1;

  const flagged = stats.malicious + stats.suspicious;

  const percentage = Math.round((flagged / total) * 100);

  let label = "Safe";
  let color = "green";

  if (percentage >= 20) {
    label = "Danger";
    color = "red";
  } else if (percentage >= 5) {
    label = "Suspicious";
    color = "yellow";
  }

  return {
    flagged,
    total,
    percentage,
    label,
    color,
  };
};
