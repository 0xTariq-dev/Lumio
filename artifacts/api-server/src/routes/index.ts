import { Router, type IRouter } from "express";
import healthRouter from "./health";
import analyzerRouter from "./analyzer";
import explanationsRouter from "./explanations";

const router: IRouter = Router();

router.use(healthRouter);
router.use(explanationsRouter);
router.use(analyzerRouter);

export default router;
