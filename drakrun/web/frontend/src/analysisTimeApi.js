import axios from "axios";

// Analysis time limits and which accelerations this server offers (GET /api/analysis-time)
export const getAnalysisTimeSettings = async () => axios.get("/analysis-time");
