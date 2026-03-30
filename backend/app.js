import express from "express";
import cors from "cors";
import helmet from "helmet";
import scanRoutes from "./routes/scan.route.js";

const app = express();

app.use(cors());
app.use(helmet());
app.use(express.json());

app.use("/api/scan", scanRoutes);

export default app;
