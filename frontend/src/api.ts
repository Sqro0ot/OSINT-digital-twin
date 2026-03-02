export async function fetchDevices() {
  const res = await fetch('http://127.0.0.1:8000/map/cameras');
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

