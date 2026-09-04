import { supabase } from "./supabase";

const API_URL = import.meta.env.VITE_API_URL || "/api";

async function authHeader() {
  const { data } = await supabase.auth.getSession();
  const token = data?.session?.access_token;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function generateDetection(technique, siem) {
  const res = await fetch(`${API_URL}/claude/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(await authHeader()) },
    body: JSON.stringify({ technique, siem }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Generation failed");
  return data;
}

export async function translateQuery(query, from, to) {
  const res = await fetch(`${API_URL}/claude/translate`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(await authHeader()) },
    body: JSON.stringify({ query, from, to }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Translation failed");
  return data;
}

export async function generateSampleData(query, tool) {
  const res = await fetch(`${API_URL}/validate/sample-data`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(await authHeader()) },
    body: JSON.stringify({ query, tool }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Sample data generation failed");
  return data;
}

export async function runAgentTest(query, tool) {
  const res = await fetch(`${API_URL}/validate/agent`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(await authHeader()) },
    body: JSON.stringify({ query, tool }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Agent test failed");
  return data;
}

export async function runBlindspotAnalysis(query, tool, name, detectionId) {
  const res = await fetch(`${API_URL}/blindspot/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(await authHeader()) },
    body: JSON.stringify({ query, tool, name, detectionId }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Blindspot analysis failed");
  return data;
}

export async function runBlindspotScan(detectionIds) {
  const res = await fetch(`${API_URL}/blindspot/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(await authHeader()) },
    body: JSON.stringify({ detectionIds }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Batch scan failed");
  return data;
}
