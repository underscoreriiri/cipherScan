import axios from "axios";

export const analyzeWithGemini = async (prompt) => {
  try {
    const res = await axios.post(
      `https://generativelanguage.googleapis.com/v1/models/gemini-2.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`,
      {
        contents: [
          {
            parts: [{ text: prompt }],
          },
        ],
      },
    );

    const text = res.data?.candidates?.[0]?.content?.parts?.[0]?.text;

    if (!text) throw new Error("No Gemini response");

    const clean = text.replace(/```json|```/g, "").trim();

    const jsonMatch = clean.match(/\{[\s\S]*\}/);

    if (!jsonMatch) throw new Error("No JSON found");

    return JSON.parse(jsonMatch[0]);
  } catch (err) {
    console.error("Gemini error:", err.response?.data || err.message);
    throw err;
  }
};
