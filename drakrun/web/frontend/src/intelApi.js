import axios from "axios";

export const getIntel = async (id, options) =>
    axios.get(`/intel/${id}`, options);
export const getIntelProviders = async () => axios.get("/intel/providers");
export const refreshIntel = async (id) => axios.post(`/intel/${id}/refresh`);
export const recheckIntel = async (id) => axios.post(`/intel/${id}/recheck`);
