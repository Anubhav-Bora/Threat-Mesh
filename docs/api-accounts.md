# External service setup

ThreatMesh can be opened in demo mode without creating any account. Live
URLhaus and ThreatFox collection needs a free abuse.ch key; an ArcGIS key is
optional for Esri-hosted basemaps; language generation is optional.

Copy `.env.example` to `.env` before adding credentials. The `.env` file is
ignored by Git. Never paste keys into source files, issue screenshots, browser
storage, or support logs.

## 1. abuse.ch Auth-Key (live URLhaus and ThreatFox)

The original project brief described these APIs as unauthenticated. Their
current APIs require a free personal Auth-Key.

1. Open [auth.abuse.ch](https://auth.abuse.ch/) and sign in.
2. Create an Auth-Key in the account portal.
3. Set `ABUSECH_AUTH_KEY` in the root `.env` file.
4. Restart the backend after changing the value.

The key belongs only in the backend. URLhaus and ThreatFox are community
services governed by fair-use and abuse.ch terms; commercial or high-volume
usage may require a different arrangement. ThreatFox's recent-query endpoint
returns at most seven days per request, so scheduled collection matters.

Official references: [URLhaus API](https://urlhaus-api.abuse.ch/),
[ThreatFox API](https://threatfox.abuse.ch/api/), and
[abuse.ch terms](https://abuse.ch/terms-of-use/).

## 2. ArcGIS Location Platform key (optional)

The ArcGIS browser key is a client credential, not a confidential server
secret. Vite embeds it in the compiled application. Keeping it out of Git
prevents accidental source disclosure, while restrictions prevent someone
from reusing the visible key elsewhere.

1. Create a free account at
   [ArcGIS Location Platform](https://location.arcgis.com/).
2. In the portal, open **Content → My content → New item → Developer
   credentials → API key credentials**.
3. Grant only the basemap privileges used by the dashboard.
4. Add HTTP-referrer allow-list entries for local development and the deployed
   site, for example `http://localhost:3000` and your exact production origin.
5. Set a sensible expiry and copy the generated key.
6. Set `VITE_ARCGIS_API_KEY` in `.env`, then rebuild the frontend because Vite
   variables are compiled at build time.

Free-tier-only use does not require enabling pay-as-you-go or adding a payment
method. Monitor the active transaction allowances in the portal; they can
change. See Esri's [API-key tutorial](https://developers.arcgis.com/documentation/security-and-authentication/api-key-authentication/tutorials/create-an-api-key/online/)
and [current pricing](https://location.arcgis.com/pricing/).

ThreatMesh's bounded flat map uses public ArcGIS World Imagery plus the ArcGIS
Boundaries and Places reference service, so no key is required. Browsers without
WebGL2 use the same ArcGIS tiles through an interactive raster renderer. A key
is reserved for premium ArcGIS services you may add later; it does not unlock
clusters, heatmaps, or location-context features in the current release.

## 3. Google Gemini key (optional report and assistant prose)

Gemini is never required for collection, scoring, clustering, ATT&CK mapping,
or detection generation. It only turns already-retrieved public OSINT facts
into prose.

1. Open [Google AI Studio](https://aistudio.google.com/) and accept the current
   terms.
2. Create a **new auth key** in an eligible Google Cloud project. Do not reuse
   an older standard key; Google has announced that standard keys will stop
   working for this API in September 2026.
3. Put the value in backend-only `GEMINI_API_KEY`.
4. Set `LLM_PROVIDER=gemini` and leave `GEMINI_MODEL=gemini-3.5-flash-lite` for the
   project's current default, or choose another generally available model after
   checking its current availability and pricing.
5. Restart the backend.

Do not prefix this variable with `VITE_` or otherwise expose it to the browser.
Free-tier quotas vary by project and model; use the limits shown in AI Studio.
Google's current terms allow free-tier inputs and outputs to be used to improve
its products, including human review. Do not send confidential, personal, or
regulated data through that tier. ThreatMesh's intended cloud workflow sends
public OSINT aggregates only; use Ollama when that boundary is unsuitable and
recheck the current terms before deployment.

Official references: [API-key setup](https://ai.google.dev/gemini-api/docs/api-key),
[models](https://ai.google.dev/gemini-api/docs/models),
[pricing](https://ai.google.dev/gemini-api/docs/pricing), and
[rate limits](https://ai.google.dev/gemini-api/docs/rate-limits).

## 4. Ollama (optional local language model)

Ollama needs no account or API key and keeps prompts on the operator-controlled
machine.

1. Install [Ollama](https://ollama.com/download) for the host platform.
2. Pull a model, for example `ollama pull llama3.1:8b` (roughly 4.9 GB).
3. Confirm Ollama is running on its default `127.0.0.1:11434` listener.
4. For a Docker Desktop deployment, set
   `OLLAMA_BASE_URL=http://host.docker.internal:11434` and
   `LLM_PROVIDER=ollama` in `.env`.
5. Restart the backend.

Ollama has no authentication by default. Do not bind it to a public network.
See its [API documentation](https://docs.ollama.com/api/introduction) and
[FAQ](https://docs.ollama.com/faq).

## Services that need no account

### Feodo Tracker

The Feodo blocklist is published without authentication under CC0. ThreatMesh
uses the documented JSON download and preserves its source metadata. See the
[Feodo blocklist documentation](https://feodotracker.abuse.ch/blocklist/).

### ip-api free endpoint

No key is required, but this provider is suitable only for a non-commercial
demo: the free endpoint is HTTP-only, capped at 45 individual requests per
minute, and governed by non-commercial terms. ThreatMesh calls it only from the
backend, stays below the documented limit, and caches results. Unencrypted
requests can reveal queried public IPs to the network path.

For a commercial or higher-assurance deployment, replace this adapter with a
licensed HTTPS provider or an offline database such as GeoLite2. See the
[ip-api JSON API](https://ip-api.com/docs/api:json) and
[legal terms](https://ip-api.com/docs/legal).

### MITRE ATT&CK

The official STIX 2.1 data needs no key. ThreatMesh filters revoked and
deprecated objects and records the ATT&CK version for reproducibility. Review
MITRE's [ATT&CK data documentation](https://attack.mitre.org/resources/attack-data-and-tools/)
and [terms of use](https://attack.mitre.org/resources/terms-of-use/).
