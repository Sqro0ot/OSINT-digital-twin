import React, { useEffect, useState, useCallback } from 'react';
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet';
import L, { DivIcon } from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Device, AlertItem } from '../App';

const API_BASE = 'http://localhost:8000';

const SEVERITY_BORDER: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#22c55e',
};
const SEVERITY_BG: Record<string, string> = {
  CRITICAL: '#fff1f0',
  HIGH:     '#fff7ed',
  MEDIUM:   '#fffbe6',
  LOW:      '#f0fdf4',
};
const SEVERITY_TEXT: Record<string, string> = {
  CRITICAL: '#b91c1c',
  HIGH:     '#c2410c',
  MEDIUM:   '#a16207',
  LOW:      '#15803d',
};

const GN_COLOR: Record<string, string> = {
  malicious:  '#ef4444',
  suspicious: '#f97316',
  benign:     '#22c55e',
  unknown:    '#94a3b8',
};

const ALERT_TYPE_LABEL: Record<string, string> = {
  NEW_VULNERABILITIES:   '🆕 New CVE',
  RISK_ELEVATED:         '📈 Risk Up',
  HIGH_EPSS_SCORE:       '☣️ High EPSS',
  EXPOSED_CRITICAL_PORT: '🔓 Open Port',
  MALICIOUS_IP_DETECTED: '🚨 Malicious IP',
  NEW_CVE:               '🆕 New CVE',
  HIGH_RISK_DEVICE:      '⚠️ High Risk',
  ZERO_DAY_DETECTED:     '💀 Zero-Day',
};

const isValidCoord = (x: unknown): x is number =>
  typeof x === 'number' && Number.isFinite(x);

const getMarkerIcon = (risk?: string | null, highlighted = false): DivIcon => {
  const r = (risk || '').toUpperCase();
  const borderColor = SEVERITY_BORDER[r] || '#0050b3';
  const bg = highlighted ? '#ffd666' : '#91d5ff';
  const boxShadow = highlighted
    ? '0 0 10px rgba(250,173,20,0.9)'
    : '0 0 6px rgba(0,0,0,0.5)';
  const html = `<div style="width:26px;height:26px;border-radius:50%;border:3px solid ${borderColor};background-color:${bg};box-shadow:${boxShadow};display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:bold;color:#000;">C</div>`;
  return L.divIcon({ className: '', html, iconSize: [30, 30], iconAnchor: [15, 15], popupAnchor: [0, -18] });
};

const FocusOnSelected: React.FC<{ devices: Device[]; selectedAssetId: number | null }> = ({ devices, selectedAssetId }) => {
  const map = useMap();
  useEffect(() => {
    if (!selectedAssetId) return;
    const dev = devices.find(d => d.id === selectedAssetId);
    if (!dev || !isValidCoord(dev.lat) || !isValidCoord(dev.lon)) return;
    map.setView([dev.lat, dev.lon], 15, { animate: true });
  }, [selectedAssetId, devices, map]);
  return null;
};

const epssColor = (score?: number | null) =>
  score == null ? '#94a3b8'
  : score >= 0.7 ? '#ef4444'
  : score >= 0.4 ? '#f97316'
  : '#22c55e';

// ─── Asset Detail Sidebar ────────────────────────────────────────────────────

interface AssetDetailProps {
  device: Device | null;
  onClose: () => void;
}

const Row: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
    padding: '5px 0', borderBottom: '1px solid #f1f5f9', gap: 8 }}>
    <span style={{ color: '#64748b', fontSize: 11, flexShrink: 0, minWidth: 110 }}>{label}</span>
    <span style={{ color: '#1e293b', fontSize: 12, fontWeight: 500, textAlign: 'right', wordBreak: 'break-all' }}>{value ?? '—'}</span>
  </div>
);

const Section: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div style={{ marginBottom: 14 }}>
    <div style={{ fontSize: 11, fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase',
      letterSpacing: 1, marginBottom: 4 }}>{title}</div>
    {children}
  </div>
);

const AssetDetail: React.FC<AssetDetailProps> = ({ device, onClose }) => {
  if (!device) return null;
  const props = (device as any).props || {};
  const gn    = props.greynoise || {};
  const whois = props.whois || {};
  const vulns: any[] = props.vulnerabilities || [];
  const ports: any[] = props.exposed_ports   || [];
  const epssMax: number | null = typeof props.epss_max === 'number' ? props.epss_max : null;
  const gnClass: string = (gn.classification || 'unknown').toLowerCase();

  return (
    <div style={{
      width: 320, borderLeft: '1px solid #e2e8f0', background: '#fff',
      display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        padding: '12px 14px', borderBottom: '1px solid #e2e8f0', background: '#f8fafc',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexShrink: 0,
      }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 13, color: '#0f172a' }}>
            {device.name || `Camera #${device.id}`}
          </div>
          <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>{props.ip || '—'}</div>
        </div>
        <button onClick={onClose} style={{
          background: 'none', border: 'none', cursor: 'pointer',
          fontSize: 18, color: '#94a3b8', lineHeight: 1,
        }}>✕</button>
      </div>

      {/* Body */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '12px 14px' }}>

        {/* Risk badges */}
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
          {device.risk_level && (
            <span style={{
              background: SEVERITY_BG[device.risk_level] || '#f5f5f5',
              color: SEVERITY_TEXT[device.risk_level] || '#374151',
              border: `1px solid ${SEVERITY_BORDER[device.risk_level] || '#d1d5db'}`,
              borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 700,
            }}>{device.risk_level}</span>
          )}
          {device.cvss_max != null && (
            <span style={{ background: '#fff7ed', color: '#c2410c',
              border: '1px solid #fed7aa', borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600 }}>
              CVSS {device.cvss_max.toFixed(1)}
            </span>
          )}
          {epssMax !== null && (
            <span style={{
              background: '#faf5ff', color: epssColor(epssMax),
              border: `1px solid ${epssColor(epssMax)}55`,
              borderRadius: 4, padding: '2px 8px', fontSize: 11, fontWeight: 600,
            }}>EPSS {(epssMax * 100).toFixed(1)}%</span>
          )}
        </div>

        {/* Basic */}
        <Section title="Основное">
          <Row label="Vendor"      value={props.vendor} />
          <Row label="Model"       value={props.model} />
          <Row label="Страна"      value={props.country} />
          <Row label="Город"       value={props.city} />
          <Row label="Last seen"   value={props.last_seen} />
          <Row label="Confidence"  value={props.confidence != null ? `${(props.confidence * 100).toFixed(0)}%` : null} />
        </Section>

        {/* GreyNoise */}
        <Section title="GreyNoise">
          <Row label="Classification" value={
            <span style={{ fontWeight: 700, color: GN_COLOR[gnClass] || '#64748b', textTransform: 'capitalize' }}>
              {gnClass}
            </span>
          } />
          <Row label="Noise" value={gn.noise != null ? (gn.noise ? '✅ Да' : '❌ Нет') : null} />
          <Row label="RIOT"  value={gn.riot  != null ? (gn.riot  ? '✅ Да' : '❌ Нет') : null} />
          {gn.name && <Row label="Name" value={gn.name} />}
          {gn.tags && gn.tags.length > 0 && (
            <Row label="Tags" value={
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                {gn.tags.map((t: string, i: number) => (
                  <span key={i} style={{
                    background: '#f1f5f9', border: '1px solid #e2e8f0',
                    borderRadius: 3, padding: '1px 5px', fontSize: 10, color: '#475569',
                  }}>{t}</span>
                ))}
              </div>
            } />
          )}
        </Section>

        {/* Whois */}
        <Section title="WHOIS / ASN">
          <Row label="ASN"          value={whois.asn ? `AS${whois.asn}` : null} />
          <Row label="Описание ASN" value={whois.asn_description} />
          <Row label="Страна ASN"   value={whois.asn_country_code} />
          <Row label="CIDR ASN"     value={whois.asn_cidr} />
          <Row label="Org"          value={whois.org} />
          <Row label="Network CIDR" value={whois.network_cidr} />
        </Section>

        {/* Exposed ports */}
        {ports.length > 0 && (
          <Section title={`Открытые порты (${ports.length})`}>
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {ports.map((p: any, i: number) => {
                const port   = p.port ?? p;
                const svc    = p.service || '';
                const isCrit = [21,22,23,80,554,8000,8080,8443,9000].includes(Number(port));
                return (
                  <span key={i} style={{
                    background: isCrit ? '#fff1f0' : '#f8fafc',
                    border: `1px solid ${isCrit ? '#fca5a5' : '#e2e8f0'}`,
                    borderRadius: 3, padding: '2px 7px', fontSize: 11,
                    color: isCrit ? '#b91c1c' : '#334155', fontWeight: isCrit ? 600 : 400,
                  }}>{port}{svc ? `/${svc}` : ''}</span>
                );
              })}
            </div>
          </Section>
        )}

        {/* Vulnerabilities */}
        <Section title={`Уязвимости (${vulns.length})`}>
          {vulns.length === 0 ? (
            <div style={{ color: '#94a3b8', fontSize: 12 }}>Нет данных</div>
          ) : (
            <div style={{ maxHeight: 220, overflowY: 'auto' }}>
              {vulns.map((v: any, i: number) => (
                <div key={i} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '4px 0', borderBottom: '1px solid #f1f5f9', fontSize: 11,
                }}>
                  <span style={{ fontWeight: 600, color: '#0f172a' }}>{v.cve_id || '?'}</span>
                  <div style={{ display: 'flex', gap: 5 }}>
                    {v.cvss_score != null && (
                      <span style={{ color: '#c2410c', fontWeight: 600 }}>CVSS {v.cvss_score}</span>
                    )}
                    {v.epss_score != null && (
                      <span style={{ color: epssColor(v.epss_score as number), fontWeight: 600 }}>
                        {((v.epss_score as number) * 100).toFixed(1)}%
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Section>

      </div>
    </div>
  );
};

// ─── MapView ──────────────────────────────────────────────────────────────────

interface MapViewProps {
  devices: Device[];
  alerts: AlertItem[];
  selectedAssetId: number | null;
  onSelectAsset: (id: number) => void;
  onAlertsCleared?: () => void;
}

const MapView: React.FC<MapViewProps> = ({ devices, alerts, selectedAssetId, onSelectAsset, onAlertsCleared }) => {
  const [clearLoading, setClearLoading] = useState(false);
  const [filter, setFilter]             = useState<string>('ALL');
  const [detailOpen, setDetailOpen]     = useState(false);

  const selectedDevice = devices.find(d => d.id === selectedAssetId) ?? null;

  useEffect(() => {
    if (selectedAssetId !== null) setDetailOpen(true);
  }, [selectedAssetId]);

  const handleClearAlerts = useCallback(async () => {
    if (!window.confirm('Очистить все алерты?')) return;
    setClearLoading(true);
    try {
      const res  = await fetch(`${API_BASE}/admin/alerts/clear`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'success' && onAlertsCleared) onAlertsCleared();
    } catch (e) { console.error(e); }
    setClearLoading(false);
  }, [onAlertsCleared]);

  const center: [number, number] = [43.2389, 76.8897];
  const visibleDevices  = devices.filter(d => isValidCoord(d.lat) && isValidCoord(d.lon));
  const alertTypes      = Array.from(new Set(alerts.map(a => a.alert_type)));
  const filteredAlerts  = filter === 'ALL' ? alerts : alerts.filter(a => a.alert_type === filter);

  return (
    <div style={{ display: 'flex', height: '100vh' }}>

      {/* Map */}
      <div style={{ flex: 1, position: 'relative' }}>
        <MapContainer center={center} zoom={12} style={{ height: '100%', width: '100%' }}>
          <TileLayer
            attribution="&copy; OpenStreetMap contributors"
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />
          <FocusOnSelected devices={visibleDevices} selectedAssetId={selectedAssetId} />
          {visibleDevices.map(device => {
            const p        = (device as any).props || {};
            const epssMax  = typeof p.epss_max === 'number' ? p.epss_max as number : null;
            const geoSource = p.geo_source ?? (device as any).geo_source ?? '—';
            const gn        = p.greynoise || {};
            const whois     = p.whois || {};
            const gnClass   = (gn.classification || 'unknown').toLowerCase();
            return (
              <Marker
                key={device.id}
                position={[device.lat, device.lon]}
                icon={getMarkerIcon(device.risk_level, device.id === selectedAssetId)}
                eventHandlers={{ click: () => onSelectAsset(device.id) }}
              >
                <Popup>
                  <div style={{ maxWidth: 260, fontSize: 12 }}>
                    <div style={{ fontWeight: 700, marginBottom: 4 }}>
                      {device.name || `Camera ${device.id}`}
                    </div>

                    {/* Risk badges */}
                    <div style={{ display: 'flex', gap: 5, marginBottom: 6, flexWrap: 'wrap' }}>
                      {device.risk_level && (
                        <span style={{
                          background: SEVERITY_BG[device.risk_level]   || '#f5f5f5',
                          color:      SEVERITY_TEXT[device.risk_level]  || '#595959',
                          border: `1px solid ${SEVERITY_BORDER[device.risk_level] || '#d9d9d9'}`,
                          borderRadius: 4, padding: '1px 6px', fontSize: 11, fontWeight: 600,
                        }}>{device.risk_level}</span>
                      )}
                      {device.cvss_max != null && (
                        <span style={{ background: '#fff7ed', color: '#c2410c',
                          border: '1px solid #fed7aa', borderRadius: 4, padding: '1px 6px', fontSize: 11 }}>
                          CVSS {device.cvss_max.toFixed(1)}
                        </span>
                      )}
                      {epssMax !== null && (
                        <span style={{
                          background: '#faf5ff', color: epssColor(epssMax),
                          border: `1px solid ${epssColor(epssMax)}55`,
                          borderRadius: 4, padding: '1px 6px', fontSize: 11, fontWeight: 600,
                        }}>EPSS {(epssMax * 100).toFixed(1)}%</span>
                      )}
                    </div>

                    {/* GreyNoise */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 3 }}>
                      <span style={{ color: '#64748b', fontSize: 11 }}>🛡 GreyNoise:</span>
                      <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'capitalize',
                        color: GN_COLOR[gnClass] || '#64748b' }}>{gnClass}</span>
                      {gn.noise && <span style={{ fontSize: 10, color: '#f97316' }}>noise</span>}
                    </div>

                    {/* Whois */}
                    {whois.asn_description && (
                      <div style={{ color: '#475569', fontSize: 11, marginBottom: 3 }}>
                        🌐 {whois.asn_description}
                        {whois.asn_country_code && ` (${whois.asn_country_code})`}
                      </div>
                    )}

                    <div style={{ color: '#6b7280', fontSize: 11, marginBottom: 4 }}>
                      📍 {geoSource}
                    </div>

                    {device.vulnerabilities && device.vulnerabilities.length > 0 ? (
                      <div style={{ color: '#c2410c', fontSize: 11, fontWeight: 600 }}>
                        ⚠️ {device.vulnerabilities.length} уязвимостей
                      </div>
                    ) : (
                      <div style={{ color: '#9ca3af', fontSize: 11 }}>Уязвимостей нет</div>
                    )}

                    <button
                      onClick={() => onSelectAsset(device.id)}
                      style={{
                        marginTop: 8, width: '100%', padding: '4px 0',
                        background: '#0f172a', color: '#fff', border: 'none',
                        borderRadius: 4, fontSize: 11, cursor: 'pointer', fontWeight: 600,
                      }}>Подробнее →</button>
                  </div>
                </Popup>
              </Marker>
            );
          })}
        </MapContainer>
      </div>

      {/* Asset detail panel */}
      {detailOpen && selectedDevice && (
        <AssetDetail
          device={selectedDevice}
          onClose={() => setDetailOpen(false)}
        />
      )}

      {/* Alerts panel */}
      <div style={{ width: 340, borderLeft: '1px solid #ddd', background: '#fafafa',
        display: 'flex', flexDirection: 'column', height: '100vh' }}>

        <div style={{ padding: '12px 12px 8px', flexShrink: 0, borderBottom: '1px solid #e5e7eb' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0, fontSize: 14 }}>Алерты</h3>
            <span style={{ fontSize: 11, color: '#9ca3af' }}>{filteredAlerts.length}</span>
          </div>
          {alertTypes.length > 0 && (
            <div style={{ display: 'flex', gap: 4, marginTop: 8, flexWrap: 'wrap' }}>
              {['ALL', ...alertTypes].map(t => (
                <button key={t} onClick={() => setFilter(t)} style={{
                  fontSize: 10, padding: '2px 7px', borderRadius: 12,
                  border:      filter === t ? '1px solid #2563eb' : '1px solid #d1d5db',
                  background:  filter === t ? '#dbeafe' : 'white',
                  color:       filter === t ? '#1d4ed8' : '#6b7280',
                  cursor: 'pointer', fontWeight: filter === t ? 600 : 400,
                }}>
                  {t === 'ALL' ? 'Все' : (ALERT_TYPE_LABEL[t] || t)}
                </button>
              ))}
            </div>
          )}
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: '8px 12px' }}>
          {filteredAlerts.length === 0 && (
            <div style={{ color: '#9ca3af', fontSize: 13, textAlign: 'center', marginTop: 24 }}>Нет алертов</div>
          )}
          {filteredAlerts.map(a => {
            const sev         = a.severity as string;
            const newCves     = a.details?.new_cves || [];
            // explicit cast to number|null to avoid TS2345
            const rawEpss     = a.details?.max_epss ?? a.details?.epss_score;
            const epssScore: number | null = typeof rawEpss === 'number' ? rawEpss : null;
            const port        = a.details?.port ?? null;
            const bg          = SEVERITY_BG[sev]     || '#fffbe6';
            const borderColor = SEVERITY_BORDER[sev] || '#d9d9d9';
            const textColor   = SEVERITY_TEXT[sev]   || '#595959';
            const typeLabel   = ALERT_TYPE_LABEL[a.alert_type] || a.alert_type;
            return (
              <div
                key={a.id}
                onClick={() => onSelectAsset(a.asset_id)}
                style={{
                  marginBottom: 8, padding: 8, borderRadius: 4, cursor: 'pointer',
                  border: a.asset_id === selectedAssetId
                    ? `2px solid ${borderColor}` : `1px solid ${borderColor}`,
                  background: bg, fontSize: 12,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div style={{ fontWeight: 600, color: textColor }}>[{a.severity}] {typeLabel}</div>
                  <div style={{ fontSize: 10, color: '#9ca3af', marginLeft: 4, flexShrink: 0 }}>#{a.asset_id}</div>
                </div>
                <div style={{ marginTop: 4, color: '#374151' }}>{a.message}</div>
                <div style={{ marginTop: 4, color: '#6b7280' }}>IP: {a.details?.ip ?? '—'}</div>
                {epssScore !== null && (
                  <div style={{ marginTop: 3, color: epssColor(epssScore), fontWeight: 600, fontSize: 11 }}>
                    ☣️ EPSS: {(epssScore * 100).toFixed(1)}%
                  </div>
                )}
                {port !== null && (
                  <div style={{ marginTop: 3, color: '#0891b2', fontSize: 11 }}>🔓 Порт: {port}</div>
                )}
                {newCves.length > 0 && (
                  <div style={{ marginTop: 3, color: '#9ca3af', fontSize: 11 }}>
                    CVEs: {newCves.slice(0, 3).join(', ')}{newCves.length > 3 && ' ...'}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <div style={{ flexShrink: 0, padding: '10px 12px', borderTop: '1px solid #e2e8f0', background: '#fafafa' }}>
          <button
            onClick={handleClearAlerts}
            disabled={clearLoading || alerts.length === 0}
            style={{
              width: '100%', padding: '8px 0', borderRadius: 6,
              border: '1px solid #d97706', background: 'transparent',
              color: clearLoading || alerts.length === 0 ? '#a8a29e' : '#b45309',
              fontWeight: 600, fontSize: 12,
              cursor: clearLoading || alerts.length === 0 ? 'not-allowed' : 'pointer',
            }}
          >
            {clearLoading ? '⏳ Очистка...' : '🗑️ Очистить алерты'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default MapView;
