import express from "express";
import { scanTarget } from "../controllers/scan.controller.js";

const router = express.Router();

router.post("/", scanTarget);

export default router;
