import { useCallback, useEffect, useRef, useState } from "react";
import { JsonRpcProvider } from "ethers";
import { registry, lookup, resolveIssuer, credentialJSON, chainJSON, provenanceOf, type Lookup, type Provenance } from "../../sdk/registry";
import deployment from "../../deployments/monadTestnet.json";

const RPC = "https://testnet-rpc.monad.xyz";
const EXPLORER = "https://testnet.monadvision.com";
const REPO = "https://github.com/calderbuild/unstripped";
const provider = new JsonRpcProvider(RPC, deployment.chainId, { staticNetwork: true });
const cc = registry(deployment.contentCredentials, provider);

const SAMPLES = [
  { file: "openai-stripped.png", label: "OpenAI image, metadata stripped" },
  { file: "gemini-stripped.png", label: "Gemini image, metadata stripped" },
  { file: "openai-credential.png", label: "OpenAI image, credential intact" },
];

type Steps = { state: "idle" | "sending" | "done" | "error"; tx?: string; block?: number; gas?: string; error?: string };
type Check = { name: string; image: string; result: Lookup };

const short = (h: string, n = 6) => `${h.slice(0, n + 2)}…${h.slice(-4)}`;
const algName = (a: number) => (a === -37 ? "PS256 · RSA, checked with modexp" : a === -7 ? "ES256 · P-256, checked with Monad's P256 precompile" : String(a));
const when = (t: number) => new Date(t * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const sourceLabel = (s: string) => s.split("/").pop()?.replace(/([A-Z])/g, " $1").toLowerCase() ?? "";

export default function App() {
  const [check, setCheck] = useState<Check | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [steps, setSteps] = useState<Steps>({ state: "idle" });
  const [recent, setRecent] = useState<{ hash: string; p: Provenance }[]>([]);
  const [drag, setDrag] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const loadRecent = useCallback(async () => {
    const n = Number(await cc.assetCount());
    const ids = Array.from({ length: Math.min(n, 8) }, (_, i) => n - 1 - i);
    const rows = await Promise.all(
      ids.map(async (i) => {
        const hash: string = await cc.assets(i);
        return { hash, p: (await provenanceOf(cc, hash))! };
      }),
    );
    setRecent(rows);
  }, []);
  useEffect(() => {
    loadRecent().catch(() => setRecent([]));
  }, [loadRecent]);

  async function inspect(name: string, bytes: Uint8Array) {
    setBusy(true);
    setError(null);
    setSteps({ state: "idle" });
    try {
      const image = URL.createObjectURL(new Blob([bytes as BlobPart]));
      setCheck({ name, image, result: await lookup(cc, bytes) });
    } catch (e) {
      setError(`Could not read the registry: ${(e as Error).message}. Check your connection and try again.`);
    } finally {
      setBusy(false);
    }
  }

  async function onFiles(files: FileList | null) {
    const f = files?.[0];
    if (f) await inspect(f.name, new Uint8Array(await f.arrayBuffer()));
  }

  async function sample(file: string) {
    const bytes = new Uint8Array(await (await fetch(`/samples/${file}`)).arrayBuffer());
    await inspect(file, bytes);
  }

  async function register() {
    const x = check?.result.extracted;
    if (!x || !check) return;
    setSteps({ state: "sending" });
    try {
      // Unknown signer (e.g. a rotated certificate): send the zero id and the chain, and the relayer
      // adds the signer first, verified on chain against its CA.
      const issuer = (await resolveIssuer(cc, x)) ?? "0x" + "00".repeat(32);
      const res = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential: credentialJSON(x, issuer), chain: chainJSON(x) }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error);
      setSteps({ state: "done", tx: body.txHash, block: body.block, gas: body.gasUsed });
      setCheck({ ...check, result: { ...check.result, provenance: await provenanceOf(cc, check.result.assetHash) } });
      loadRecent();
    } catch (e) {
      setSteps({ state: "error", error: (e as Error).message });
    }
  }

  return (
    <div className="page">
      <header className="bar">
        <a className="mark" href="/">
          <Tag /> Unstripped
        </a>
        <span className="net">
          Monad testnet ·{" "}
          <a href={`${EXPLORER}/address/${deployment.contentCredentials}`} target="_blank" rel="noreferrer">
            registry {short(deployment.contentCredentials, 4)}
          </a>
        </span>
      </header>

      <main>
        <section className="hero">
          <div className="pitch">
            <h1>
              Where did this
              <br />
              image come from?
            </h1>
            <p className="lede">
              OpenAI, Google and a growing list of cameras sign every image they produce. The signature lives in the
              file's metadata, and most sites delete it on upload. Unstripped keeps a verified copy of each signature on
              Monad, so the answer survives the upload.
            </p>
            <div className="samples">
              <span className="eyebrow">No image at hand? Try one</span>
              {SAMPLES.map((s) => (
                <button key={s.file} onClick={() => sample(s.file)} disabled={busy}>
                  {s.label}
                </button>
              ))}
            </div>
          </div>

          <div
            className={`lightbox${drag ? " drag" : ""}${check ? " has" : ""}`}
            onDragOver={(e) => (e.preventDefault(), setDrag(true))}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => (e.preventDefault(), setDrag(false), onFiles(e.dataTransfer.files))}
          >
            {check ? (
              <figure className="plate">
                <img src={check.image} alt={check.name} />
                <Verdict c={check} steps={steps} onRegister={register} />
              </figure>
            ) : (
              <button className="drop" onClick={() => input.current?.click()} disabled={busy}>
                <strong>{busy ? "Checking the registry…" : "Drop a PNG here"}</strong>
                <span>or choose a file. The image stays in your browser; only its hash is looked up.</span>
              </button>
            )}
            <input ref={input} type="file" accept="image/png" hidden onChange={(e) => onFiles(e.target.files)} />
            {check && (
              <button className="again" onClick={() => input.current?.click()} disabled={busy}>
                Check another image
              </button>
            )}
          </div>
          {error && <p className="error">{error}</p>}
        </section>

        <section className="how">
          <h2>What the chain checks before it records anything</h2>
          <ol>
            <li>
              <h3>The certificate</h3>
              <p>
                The signing certificate must be issued by a CA on the C2PA trust list. The contract parses the X.509
                certificate and verifies the CA's signature over it.
              </p>
            </li>
            <li>
              <h3>The claim signature</h3>
              <p>
                The manifest's claim must be signed by that certificate's key: RSA-PSS through the modexp precompile, or
                ECDSA P-256 through Monad's native P256 precompile.
              </p>
            </li>
            <li>
              <h3>The binding to the pixels</h3>
              <p>
                The signed claim lists the hash of the image bytes. The contract checks that hash against the signed
                assertion and stores it, along with whether the signer declared the image AI-generated.
              </p>
            </li>
          </ol>
          <p className="aside">
            Nobody can add a record the signer did not sign, including whoever submits it. The trust anchors were sealed
            at deployment; there is no admin key.
          </p>
        </section>

        <section className="recent">
          <h2>Recently recorded</h2>
          {recent.length === 0 ? (
            <p className="muted">Loading records from Monad…</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Image hash</th>
                  <th>Signed by</th>
                  <th>Made with</th>
                  <th>AI-generated</th>
                  <th>Recorded</th>
                </tr>
              </thead>
              <tbody>
                {recent.map(({ hash, p }) => (
                  <tr key={hash}>
                    <td className="mono">{short(hash, 8)}</td>
                    <td>{p.signerOrg}</td>
                    <td>{p.generator}</td>
                    <td>{p.aiGenerated ? "Yes" : "Not declared"}</td>
                    <td>{when(p.registeredAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section className="dev">
          <h2>Use it from your app</h2>
          <p>
            Any contract or client can read a record. A marketplace can label AI art at mint, a social app can show where a
            reposted image came from, an agent can check a picture before it cites it.
          </p>
          <div className="code">
            <figure>
              <figcaption>Solidity</figcaption>
              <pre>{`interface IContentCredentials {
  function isAIGenerated(bytes32 imageHash) external view returns (bool);
}

// sha256 of the image as your users upload it
bool ai = IContentCredentials(${short(deployment.contentCredentials, 4)})
  .isAIGenerated(imageHash);`}</pre>
            </figure>
            <figure>
              <figcaption>TypeScript</figcaption>
              <pre>{`import { registry, lookup } from "unstripped/sdk/registry";

const cc = registry(REGISTRY, provider);
const { provenance } = await lookup(cc, imageBytes);
// { signerOrg: "OpenAI OpCo, LLC", aiGenerated: true, ... }`}</pre>
            </figure>
          </div>
        </section>
      </main>

      <footer>
        <span>Unstripped · C2PA Content Credentials, verified on Monad</span>
        <a href={REPO} target="_blank" rel="noreferrer">
          Source and docs on GitHub
        </a>
      </footer>
    </div>
  );
}

function Verdict({ c, steps, onRegister }: { c: Check; steps: Steps; onRegister: () => void }) {
  const { provenance: p, hadManifest, assetHash } = c.result;
  if (p) {
    return (
      <div className="tag found" role="status">
        <span className="hole" />
        <p className="kicker">{hadManifest ? "Credential verified on chain" : "Recovered from the chain"}</p>
        <p className="who">{p.signerOrg}</p>
        <dl>
          <dt>Made with</dt>
          <dd>{p.generator}</dd>
          <dt>Source</dt>
          <dd className={p.aiGenerated ? "ai" : ""}>{p.aiGenerated ? "AI-generated" : sourceLabel(p.sourceType) || "Not declared"}</dd>
          <dt>Signature</dt>
          <dd>{algName(p.alg)}</dd>
          <dt>Recorded</dt>
          <dd>{when(p.registeredAt)}</dd>
          <dt>Image hash</dt>
          <dd className="mono">{short(assetHash, 10)}</dd>
        </dl>
        {!hadManifest && <p className="note">This file carries no metadata. Its bytes match the image the signer signed.</p>}
        {steps.tx && (
          <a className="tx" href={`${EXPLORER}/tx/${steps.tx}`} target="_blank" rel="noreferrer">
            Recorded in block {steps.block} · view transaction
          </a>
        )}
      </div>
    );
  }
  if (hadManifest) {
    return (
      <div className="tag pending" role="status">
        <span className="hole" />
        <p className="kicker">Credential found in the file</p>
        <p className="who">Not on chain yet</p>
        <p className="note">
          Record it now and anyone holding a stripped copy of this image can look it up. The registry verifies the
          signature itself; you need no wallet.
        </p>
        {steps.state === "error" && <p className="note bad">{steps.error}</p>}
        <button className="record" onClick={onRegister} disabled={steps.state === "sending"}>
          {steps.state === "sending" ? "Verifying on Monad…" : "Record this credential"}
        </button>
      </div>
    );
  }
  return (
    <div className="tag none" role="status">
      <span className="hole" />
      <p className="kicker">No record</p>
      <p className="who">Nothing on chain for these exact bytes</p>
      <p className="note">
        Either no signer recorded this image, or the copy was re-encoded, which changes every byte. Unstripped matches
        exact copies with the metadata removed.
      </p>
      {c.result.extractError && !c.result.extractError.startsWith("no C2PA") && <p className="note">{c.result.extractError}.</p>}
    </div>
  );
}

function Tag() {
  return (
    <svg viewBox="0 0 32 32" width="22" height="22" aria-hidden="true">
      <path d="M4 9.5 11.5 2H28a2 2 0 0 1 2 2v16.5L22.5 28H6a2 2 0 0 1-2-2z" fill="currentColor" />
      <circle cx="11" cy="9" r="2.4" fill="var(--fog)" />
    </svg>
  );
}
