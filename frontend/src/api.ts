const API_BASE = process.env.REACT_APP_API_URL 
  || `http://${window.location.hostname}:8000`;

export async function fetchDevices() {
  const res = await fetch(`${API_BASE}/map/cameras`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
