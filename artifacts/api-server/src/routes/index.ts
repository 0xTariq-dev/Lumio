import { Router, type IRouter } from "express";
import healthRouter from "./health";
import analyzerRouter from "./analyzer";
import explanationsRouter from "./explanations";
import agentRouter from "./agent";

const router: IRouter = Router();

router.use(healthRouter);
router.use(explanationsRouter);
router.use(agentRouter);
router.use(analyzerRouter);

export default router;
