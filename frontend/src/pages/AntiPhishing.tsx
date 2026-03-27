import React, { useEffect, useMemo, useState } from 'react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8080';

type ApiResult =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; data: any }
  | { status: 'error'; error: string; data?: any };

const initialPsychographicForm = {
  user_id: 'usr-finance-17',
  display_name: 'Priya Malhotra',
  department: 'Finance',
  role: 'Finance Director',
  seniority_level: 4,
  financial_authority: true,
  public_exposure_score: 0.72,
  email_open_rate: 0.84,
  phishing_sim_fail_rate: 0.31,
  past_incidents: 1,
  access_level: 4,
  travel_frequency: 0.45,
  work_hours_variance: 0.22,
  social_connections: 128,
};

async function parseResponse(res: Response) {
  const text = await res.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

async function fileToBase64(file: File) {
  const buffer = await file.arrayBuffer();
  return arrayBufferToBase64(buffer);
}

function arrayBufferToBase64(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function mergeChannels(decoded: AudioBuffer) {
  const length = decoded.length;
  const channelCount = decoded.numberOfChannels;
  if (channelCount === 1) {
    return new Float32Array(decoded.getChannelData(0));
  }

  const mono = new Float32Array(length);
  for (let channel = 0; channel < channelCount; channel += 1) {
    const data = decoded.getChannelData(channel);
    for (let index = 0; index < length; index += 1) {
      mono[index] += data[index] / channelCount;
    }
  }
  return mono;
}

async function audioFileToVoicePayload(file: File) {
  const AudioContextCtor =
    window.AudioContext ||
    (window as Window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;

  if (!AudioContextCtor) {
    throw new Error('This browser does not support the Web Audio API.');
  }

  const inputContext = new AudioContextCtor();
  try {
    const arrayBuffer = await file.arrayBuffer();
    const decoded = await inputContext.decodeAudioData(arrayBuffer.slice(0));
    const mono = mergeChannels(decoded);

    let rendered = mono;
    let sampleRate = decoded.sampleRate;

    if (decoded.sampleRate !== 16000) {
      const offline = new OfflineAudioContext(1, Math.ceil(decoded.duration * 16000), 16000);
      const resampleBuffer = offline.createBuffer(1, mono.length, decoded.sampleRate);
      resampleBuffer.copyToChannel(mono, 0);
      const source = offline.createBufferSource();
      source.buffer = resampleBuffer;
      source.connect(offline.destination);
      source.start(0);
      const resampled = await offline.startRendering();
      rendered = new Float32Array(resampled.getChannelData(0));
      sampleRate = 16000;
    }

    return {
      audio_b64: arrayBufferToBase64(rendered.buffer),
      sample_rate: sampleRate,
    };
  } catch (error) {
    if (file.name.toLowerCase().endsWith('.f32') || file.type === 'application/octet-stream') {
      const buffer = await file.arrayBuffer();
      return {
        audio_b64: arrayBufferToBase64(buffer),
        sample_rate: 16000,
      };
    }
    throw error;
  } finally {
    void inputContext.close();
  }
}

function ResultCard({ title, result }: { title: string; result: ApiResult }) {
  if (result.status === 'idle') {
    return (
      <div className="rounded-xl border border-dashed border-[#D8E3F7] bg-[#F8FAFF] p-4 text-sm text-slate-500">
        Run {title.toLowerCase()} to see live output here.
      </div>
    );
  }

  if (result.status === 'loading') {
    return (
      <div className="rounded-xl border border-[#D8E3F7] bg-[#F8FAFF] p-4 text-sm text-slate-600">
        Processing {title.toLowerCase()}...
      </div>
    );
  }

  if (result.status === 'error') {
    return (
      <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
        <div className="font-semibold">Request failed</div>
        <div className="mt-1 whitespace-pre-wrap break-words">{result.error}</div>
        {result.data && (
          <pre className="mt-3 overflow-x-auto rounded-lg bg-white/70 p-3 text-xs text-red-900">
            {JSON.stringify(result.data, null, 2)}
          </pre>
        )}
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-[#D8E3F7] bg-[#F8FAFF] p-4">
      <pre className="overflow-x-auto whitespace-pre-wrap break-words text-xs text-slate-700">
        {JSON.stringify(result.data, null, 2)}
      </pre>
    </div>
  );
}

function SectionCard({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <div className="card">
      <div className="flex flex-col gap-1 border-b border-[#E2E9FA] pb-3">
        <h2 className="text-lg font-semibold text-slate-900">{title}</h2>
        <p className="text-sm text-slate-500">{subtitle}</p>
      </div>
      <div className="mt-4">{children}</div>
    </div>
  );
}

export default function AntiPhishing({ authToken }: { authToken: string }) {
  const [stats, setStats] = useState<any>(null);
  const [modelStatus, setModelStatus] = useState<any>(null);
  const [summaryError, setSummaryError] = useState<string | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(true);

  const [emailForm, setEmailForm] = useState({
    sender: 'finance-approvals@corp-secure-mail.com',
    subject: 'Immediate payment approval required',
    text: 'Your corporate account will expire unless you verify your login immediately and approve the pending wire transfer.',
  });
  const [emailResult, setEmailResult] = useState<ApiResult>({ status: 'idle' });

  const [urlValue, setUrlValue] = useState('https://paypa1-login-verification.example/security-check');
  const [urlResult, setUrlResult] = useState<ApiResult>({ status: 'idle' });

  const [voiceFile, setVoiceFile] = useState<File | null>(null);
  const [voiceResult, setVoiceResult] = useState<ApiResult>({ status: 'idle' });

  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imageResult, setImageResult] = useState<ApiResult>({ status: 'idle' });

  const [psychographicForm, setPsychographicForm] = useState(initialPsychographicForm);
  const [psychographicResult, setPsychographicResult] = useState<ApiResult>({ status: 'idle' });

  const [detonationForm, setDetonationForm] = useState({
    url: 'http://localhost:8003/health',
    timeout_ms: 5000,
  });
  const [detonationResult, setDetonationResult] = useState<ApiResult>({ status: 'idle' });

  const [intelForm, setIntelForm] = useState({
    ioc: 'paypa1-login-verification.example',
    type: 'domain',
  });
  const [intelResult, setIntelResult] = useState<ApiResult>({ status: 'idle' });

  const [feedbackForm, setFeedbackForm] = useState({
    text: 'Urgent payroll issue. Verify your account now to avoid suspension.',
    predicted_label: 'legitimate',
    correct_label: 'phishing',
  });
  const [feedbackResult, setFeedbackResult] = useState<ApiResult>({ status: 'idle' });

  const [scenarioResult, setScenarioResult] = useState<ApiResult>({ status: 'idle' });

  const hasDetonationFallback = useMemo(() => {
    if (detonationResult.status !== 'success') {
      return false;
    }
    const errorMessage = String(detonationResult.data?.error_message || '');
    return errorMessage.includes('degraded_mode=http_fallback');
  }, [detonationResult]);

  useEffect(() => {
    let cancelled = false;

    const loadSummary = async () => {
      setSummaryLoading(true);
      setSummaryError(null);

      try {
        const [statsRes, modelRes] = await Promise.all([
          fetch(`${API_BASE}/api/v1/phishing/stats`, {
            headers: { Authorization: `Bearer ${authToken}` },
          }),
          fetch(`${API_BASE}/api/v1/phishing/model/status`, {
            headers: { Authorization: `Bearer ${authToken}` },
          }),
        ]);

        const [statsPayload, modelPayload] = await Promise.all([
          parseResponse(statsRes),
          parseResponse(modelRes),
        ]);

        if (cancelled) {
          return;
        }

        if (!statsRes.ok || !modelRes.ok) {
          throw new Error(
            typeof statsPayload === 'object' && statsPayload && 'error' in statsPayload
              ? String((statsPayload as any).error)
              : typeof modelPayload === 'object' && modelPayload && 'error' in modelPayload
              ? String((modelPayload as any).error)
              : 'Unable to load anti-phishing summary.',
          );
        }

        setStats(statsPayload);
        setModelStatus(modelPayload);
      } catch (error) {
        if (!cancelled) {
          setSummaryError(error instanceof Error ? error.message : 'Unable to load anti-phishing summary.');
        }
      } finally {
        if (!cancelled) {
          setSummaryLoading(false);
        }
      }
    };

    void loadSummary();
    return () => {
      cancelled = true;
    };
  }, [authToken]);

  async function requestJson(path: string, init?: RequestInit) {
    const headers = new Headers(init?.headers || {});
    headers.set('Authorization', `Bearer ${authToken}`);
    if (!headers.has('Content-Type') && init?.body) {
      headers.set('Content-Type', 'application/json');
    }

    const res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers,
    });
    const payload = await parseResponse(res);

    if (!res.ok) {
      const errorMessage =
        typeof payload === 'object' && payload
          ? String((payload as any).detail || (payload as any).error || `Request failed (${res.status})`)
          : `Request failed (${res.status})`;
      throw { message: errorMessage, payload };
    }

    return payload;
  }

  async function runAction(
    setter: React.Dispatch<React.SetStateAction<ApiResult>>,
    action: () => Promise<any>,
    onSuccess?: (payload: any) => void,
  ) {
    setter({ status: 'loading' });
    try {
      const payload = await action();
      setter({ status: 'success', data: payload });
      onSuccess?.(payload);
    } catch (error: any) {
      setter({
        status: 'error',
        error: error?.message || 'Request failed.',
        data: error?.payload,
      });
    }
  }

  return (
    <div className="space-y-6">
      <div className="card overflow-hidden">
        <div className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
          <div>
            <div className="inline-flex items-center rounded-full border border-[#D8E3F7] bg-[#EFF4FF] px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-[#517EF9]">
              Anti-Phishing Workbench
            </div>
            <h1 className="mt-4 text-3xl font-bold tracking-tight text-slate-900">
              Run every anti-phishing workflow from the frontend
            </h1>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-600">
              This workspace exposes the live backend tools for email and URL analysis, voice and image deepfake detection,
              psychographic risk scoring, sandbox detonation, IOC enrichment, analyst feedback, and the guided phishing scenario.
            </p>
          </div>
          <div className="rounded-2xl border border-[#D8E3F7] bg-[#F8FAFF] p-4">
            <div className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">Runtime Summary</div>
            {summaryLoading ? (
              <div className="mt-4 text-sm text-slate-500">Loading service summary...</div>
            ) : summaryError ? (
              <div className="mt-4 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">{summaryError}</div>
            ) : (
              <div className="mt-4 grid grid-cols-2 gap-3">
                <SummaryMetric label="Emails analyzed" value={stats?.emails_analyzed ?? 0} />
                <SummaryMetric label="URLs analyzed" value={stats?.urls_analyzed ?? 0} />
                <SummaryMetric label="Voice samples" value={stats?.voice_analyzed ?? 0} />
                <SummaryMetric label="Detonations" value={stats?.detonations_run ?? 0} />
                <SummaryMetric label="IOCs enriched" value={stats?.iocs_enriched ?? 0} />
                <SummaryMetric label="Feedback queued" value={modelStatus?.pending_feedback_count ?? 0} />
              </div>
            )}
          </div>
        </div>
      </div>

      {hasDetonationFallback && (
        <div className="rounded-xl border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-800">
          URL detonation is currently running in degraded HTTP fallback mode because full Playwright Chromium is unavailable in this environment.
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard
          title="Email Phishing Analysis"
          subtitle="Classify suspicious email content and inspect the triggered features."
        >
          <div className="space-y-3">
            <input
              value={emailForm.sender}
              onChange={(e) => setEmailForm((prev) => ({ ...prev, sender: e.target.value }))}
              className="w-full rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm text-slate-700 outline-none focus:border-[#517EF9]"
              placeholder="Sender"
            />
            <input
              value={emailForm.subject}
              onChange={(e) => setEmailForm((prev) => ({ ...prev, subject: e.target.value }))}
              className="w-full rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm text-slate-700 outline-none focus:border-[#517EF9]"
              placeholder="Subject"
            />
            <textarea
              value={emailForm.text}
              onChange={(e) => setEmailForm((prev) => ({ ...prev, text: e.target.value }))}
              rows={5}
              className="w-full rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm text-slate-700 outline-none focus:border-[#517EF9]"
              placeholder="Email body"
            />
            <button
              onClick={() =>
                runAction(setEmailResult, () =>
                  requestJson('/api/v1/phishing/analyze/email', {
                    method: 'POST',
                    body: JSON.stringify(emailForm),
                  }),
                )
              }
              className="rounded-lg bg-[#517EF9] px-4 py-2 text-sm font-medium text-white hover:bg-[#436FE8]"
            >
              Analyze Email
            </button>
            <ResultCard title="Email analysis" result={emailResult} />
          </div>
        </SectionCard>

        <SectionCard
          title="URL Reputation Analysis"
          subtitle="Inspect URL phishing signals, redirect behavior, and risk scoring."
        >
          <div className="space-y-3">
            <input
              value={urlValue}
              onChange={(e) => setUrlValue(e.target.value)}
              className="w-full rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm text-slate-700 outline-none focus:border-[#517EF9]"
              placeholder="https://example.com"
            />
            <button
              onClick={() =>
                runAction(setUrlResult, () =>
                  requestJson('/api/v1/phishing/analyze/url', {
                    method: 'POST',
                    body: JSON.stringify({ url: urlValue }),
                  }),
                )
              }
              className="rounded-lg bg-[#14213D] px-4 py-2 text-sm font-medium text-white hover:bg-[#0F1A31]"
            >
              Analyze URL
            </button>
            <ResultCard title="URL analysis" result={urlResult} />
          </div>
        </SectionCard>

        <SectionCard
          title="Voice Deepfake Analysis"
          subtitle="Upload audio and send it through the voice phishing detector after browser-side PCM conversion."
        >
          <div className="space-y-3">
            <input
              type="file"
              accept="audio/*,.wav,.mp3,.ogg,.m4a,.f32"
              onChange={(e) => setVoiceFile(e.target.files?.[0] || null)}
              className="block w-full text-sm text-slate-600"
            />
            <p className="text-xs text-slate-500">
              Preferred formats: WAV or MP3. Raw float32 PCM `.f32` also works and is treated as 16 kHz mono.
            </p>
            <button
              onClick={() =>
                runAction(setVoiceResult, async () => {
                  if (!voiceFile) {
                    throw { message: 'Choose an audio file first.' };
                  }
                  const payload = await audioFileToVoicePayload(voiceFile);
                  return requestJson('/api/v1/phishing/analyze/voice', {
                    method: 'POST',
                    body: JSON.stringify(payload),
                  });
                })
              }
              className="rounded-lg bg-[#7C3AED] px-4 py-2 text-sm font-medium text-white hover:bg-[#6D28D9]"
            >
              Analyze Voice
            </button>
            <ResultCard title="Voice analysis" result={voiceResult} />
          </div>
        </SectionCard>

        <SectionCard
          title="Image Deepfake Analysis"
          subtitle="Upload a suspicious image for EXIF, ELA, and manipulation heuristics."
        >
          <div className="space-y-3">
            <input
              type="file"
              accept="image/*,.png,.jpg,.jpeg,.webp"
              onChange={(e) => setImageFile(e.target.files?.[0] || null)}
              className="block w-full text-sm text-slate-600"
            />
            <button
              onClick={() =>
                runAction(setImageResult, async () => {
                  if (!imageFile) {
                    throw { message: 'Choose an image file first.' };
                  }
                  const image_b64 = await fileToBase64(imageFile);
                  return requestJson('/api/v1/phishing/analyze/image', {
                    method: 'POST',
                    body: JSON.stringify({ image_b64 }),
                  });
                })
              }
              className="rounded-lg bg-[#0F766E] px-4 py-2 text-sm font-medium text-white hover:bg-[#0B5F59]"
            >
              Analyze Image
            </button>
            <ResultCard title="Image analysis" result={imageResult} />
          </div>
        </SectionCard>

        <SectionCard
          title="Psychographic Risk Profiling"
          subtitle="Score user susceptibility to social engineering using role, exposure, and behavioral attributes."
        >
          <div className="grid gap-3 md:grid-cols-2">
            <input value={psychographicForm.user_id} onChange={(e) => setPsychographicForm((prev) => ({ ...prev, user_id: e.target.value }))} className="rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm" placeholder="User ID" />
            <input value={psychographicForm.display_name} onChange={(e) => setPsychographicForm((prev) => ({ ...prev, display_name: e.target.value }))} className="rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm" placeholder="Display name" />
            <input value={psychographicForm.department} onChange={(e) => setPsychographicForm((prev) => ({ ...prev, department: e.target.value }))} className="rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm" placeholder="Department" />
            <input value={psychographicForm.role} onChange={(e) => setPsychographicForm((prev) => ({ ...prev, role: e.target.value }))} className="rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm" placeholder="Role" />
            <NumberField label="Seniority" value={psychographicForm.seniority_level} onChange={(value) => setPsychographicForm((prev) => ({ ...prev, seniority_level: value }))} />
            <NumberField label="Access level" value={psychographicForm.access_level} onChange={(value) => setPsychographicForm((prev) => ({ ...prev, access_level: value }))} />
            <NumberField label="Public exposure" step={0.01} value={psychographicForm.public_exposure_score} onChange={(value) => setPsychographicForm((prev) => ({ ...prev, public_exposure_score: value }))} />
            <NumberField label="Open rate" step={0.01} value={psychographicForm.email_open_rate} onChange={(value) => setPsychographicForm((prev) => ({ ...prev, email_open_rate: value }))} />
            <NumberField label="Sim fail rate" step={0.01} value={psychographicForm.phishing_sim_fail_rate} onChange={(value) => setPsychographicForm((prev) => ({ ...prev, phishing_sim_fail_rate: value }))} />
            <NumberField label="Past incidents" value={psychographicForm.past_incidents} onChange={(value) => setPsychographicForm((prev) => ({ ...prev, past_incidents: value }))} />
            <NumberField label="Travel frequency" step={0.01} value={psychographicForm.travel_frequency} onChange={(value) => setPsychographicForm((prev) => ({ ...prev, travel_frequency: value }))} />
            <NumberField label="Work hours variance" step={0.01} value={psychographicForm.work_hours_variance} onChange={(value) => setPsychographicForm((prev) => ({ ...prev, work_hours_variance: value }))} />
            <NumberField label="Social connections" value={psychographicForm.social_connections} onChange={(value) => setPsychographicForm((prev) => ({ ...prev, social_connections: value }))} />
            <label className="flex items-center gap-2 rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm text-slate-700">
              <input
                type="checkbox"
                checked={psychographicForm.financial_authority}
                onChange={(e) => setPsychographicForm((prev) => ({ ...prev, financial_authority: e.target.checked }))}
              />
              Financial authority
            </label>
          </div>
          <div className="mt-4">
            <button
              onClick={() =>
                runAction(setPsychographicResult, () =>
                  requestJson('/api/v1/phishing/analyze/psychographic', {
                    method: 'POST',
                    body: JSON.stringify(psychographicForm),
                  }),
                )
              }
              className="rounded-lg bg-[#F59E0B] px-4 py-2 text-sm font-medium text-white hover:bg-[#D97706]"
            >
              Assess Psychographic Risk
            </button>
          </div>
          <div className="mt-3">
            <ResultCard title="Psychographic assessment" result={psychographicResult} />
          </div>
        </SectionCard>

        <SectionCard
          title="Sandbox Detonation"
          subtitle="Run URL detonation and inspect whether the service is using full-browser or degraded fallback mode."
        >
          <div className="space-y-3">
            <input
              value={detonationForm.url}
              onChange={(e) => setDetonationForm((prev) => ({ ...prev, url: e.target.value }))}
              className="w-full rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm"
              placeholder="Target URL"
            />
            <NumberField
              label="Timeout (ms)"
              value={detonationForm.timeout_ms}
              onChange={(value) => setDetonationForm((prev) => ({ ...prev, timeout_ms: value }))}
            />
            <button
              onClick={() =>
                runAction(setDetonationResult, () =>
                  requestJson('/api/v1/phishing/analyze/detonate', {
                    method: 'POST',
                    body: JSON.stringify(detonationForm),
                  }),
                )
              }
              className="rounded-lg bg-[#DC2626] px-4 py-2 text-sm font-medium text-white hover:bg-[#B91C1C]"
            >
              Detonate URL
            </button>
            <ResultCard title="Detonation" result={detonationResult} />
          </div>
        </SectionCard>

        <SectionCard
          title="Threat Intel Enrichment"
          subtitle="Enrich a URL, domain, IP, or hash and inspect the resulting reputation data."
        >
          <div className="space-y-3">
            <input
              value={intelForm.ioc}
              onChange={(e) => setIntelForm((prev) => ({ ...prev, ioc: e.target.value }))}
              className="w-full rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm"
              placeholder="IOC"
            />
            <select
              value={intelForm.type}
              onChange={(e) => setIntelForm((prev) => ({ ...prev, type: e.target.value }))}
              className="w-full rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm"
            >
              <option value="url">URL</option>
              <option value="ip">IP</option>
              <option value="domain">Domain</option>
              <option value="hash">Hash</option>
            </select>
            <button
              onClick={() =>
                runAction(setIntelResult, () =>
                  requestJson('/api/v1/phishing/intel/enrich', {
                    method: 'POST',
                    body: JSON.stringify(intelForm),
                  }),
                )
              }
              className="rounded-lg bg-[#0891B2] px-4 py-2 text-sm font-medium text-white hover:bg-[#0E7490]"
            >
              Enrich IOC
            </button>
            <ResultCard title="Threat intel" result={intelResult} />
          </div>
        </SectionCard>

        <SectionCard
          title="Analyst Feedback Loop"
          subtitle="Submit corrections so the phishing model queue reflects analyst-reviewed ground truth."
        >
          <div className="space-y-3">
            <textarea
              rows={4}
              value={feedbackForm.text}
              onChange={(e) => setFeedbackForm((prev) => ({ ...prev, text: e.target.value }))}
              className="w-full rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm"
              placeholder="Analyst-reviewed sample"
            />
            <div className="grid gap-3 md:grid-cols-2">
              <select
                value={feedbackForm.predicted_label}
                onChange={(e) => setFeedbackForm((prev) => ({ ...prev, predicted_label: e.target.value }))}
                className="rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm"
              >
                <option value="legitimate">legitimate</option>
                <option value="phishing">phishing</option>
                <option value="spear_phishing">spear_phishing</option>
                <option value="bec">bec</option>
              </select>
              <select
                value={feedbackForm.correct_label}
                onChange={(e) => setFeedbackForm((prev) => ({ ...prev, correct_label: e.target.value }))}
                className="rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm"
              >
                <option value="legitimate">legitimate</option>
                <option value="phishing">phishing</option>
                <option value="spear_phishing">spear_phishing</option>
                <option value="bec">bec</option>
              </select>
            </div>
            <button
              onClick={() =>
                runAction(
                  setFeedbackResult,
                  () =>
                    requestJson('/api/v1/phishing/feedback', {
                      method: 'POST',
                      body: JSON.stringify(feedbackForm),
                    }),
                  (payload) => {
                    setModelStatus((prev: any) =>
                      prev
                        ? {
                            ...prev,
                            pending_feedback_count:
                              typeof payload?.pending_feedback_count === 'number'
                                ? payload.pending_feedback_count
                                : prev.pending_feedback_count,
                          }
                        : prev,
                    );
                  },
                )
              }
              className="rounded-lg bg-[#059669] px-4 py-2 text-sm font-medium text-white hover:bg-[#047857]"
            >
              Submit Feedback
            </button>
            <ResultCard title="Feedback submission" result={feedbackResult} />
          </div>
        </SectionCard>
      </div>

      <SectionCard
        title="Guided Phishing Scenario"
        subtitle="Run the composite hackathon flow that chains email analysis, URL analysis, psychographic scoring, threat intel, and incident escalation."
      >
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={() =>
              runAction(setScenarioResult, () =>
                requestJson('/api/v1/demo/phishing-scenario', {
                  method: 'POST',
                }),
              )
            }
            className="rounded-lg bg-[#111827] px-4 py-2 text-sm font-medium text-white hover:bg-black"
          >
            Run Scenario
          </button>
          <span className="text-sm text-slate-500">
            Useful when you want a single frontend action that exercises several anti-phishing capabilities at once.
          </span>
        </div>
        <div className="mt-4">
          <ResultCard title="Scenario" result={scenarioResult} />
        </div>
      </SectionCard>
    </div>
  );
}

function SummaryMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-[#D8E3F7] bg-white p-3">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 text-xl font-semibold text-slate-900">{Number(value || 0).toLocaleString()}</div>
    </div>
  );
}

function NumberField({
  label,
  value,
  onChange,
  step = 1,
}: {
  label: string;
  value: number;
  onChange: (value: number) => void;
  step?: number;
}) {
  return (
    <label className="rounded-lg border border-[#D8E3F7] px-3 py-2 text-sm text-slate-700">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <input
        type="number"
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="mt-1 w-full bg-transparent outline-none"
      />
    </label>
  );
}
