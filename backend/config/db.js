import mongoose from "mongoose";

export const connectDB = async () => {
  try {
    console.log("Connecting to MongoDB...");

    const conn = await mongoose.connect(process.env.MONGO_URI, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 10000,
    });

    await new Promise((resolve, reject) => {
      if (mongoose.connection.readyState === 1) return resolve();

      mongoose.connection.once("connected", resolve);
      mongoose.connection.once("error", reject);
    });

    console.log(`MongoDB READY at ${conn.connection.host}`);
  } catch (err) {
    console.error(" DB connection failed:", err);
    process.exit(1);
  }
};
