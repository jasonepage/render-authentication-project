/**
 * demo.js — drives the WebAuthn live walkthrough.
 *
 * Each numbered step calls a /demo/* endpoint, renders the decoded payload,
 * and unlocks the next step. State is per-session; nothing persists.
 */

// ---------------------------------------------------------------------------
// base64url <-> ArrayBuffer
// ---------------------------------------------------------------------------

function b64urlToBuffer(b64url) {
    const padded = b64url.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - b64url.length % 4) % 4);
    const binary = atob(padded);
    const buf = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
    return buf.buffer;
}

function bufferToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

function getStep(id) {
    return document.querySelector(`[data-step="${id}"]`);
}

function setStatus(stepId, status, label) {
    const step = getStep(stepId);
    if (!step) return;
    const badge = step.querySelector('[data-status]');
    badge.dataset.statusValue = status;
    badge.textContent = label || status;
    step.classList.toggle('done', status === 'done');
    step.classList.toggle('error', status === 'error');
    step.classList.toggle('locked', status === 'locked');
    step.classList.toggle('active', status === 'active');
}

function unlockStep(stepId) {
    const step = getStep(stepId);
    if (!step) return;
    step.classList.remove('locked');
    setStatus(stepId, 'active', 'ready');
    const btn = step.querySelector('button[data-action]');
    if (btn) btn.disabled = false;
}

function setOutput(stepId, html) {
    const step = getStep(stepId);
    if (!step) return;
    step.querySelector('[data-output]').innerHTML = html;
}

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function code(value, lang = 'json') {
    const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
    return `<pre class="demo-code"><code data-lang="${lang}">${escapeHtml(text)}</code></pre>`;
}

function panel(title, body) {
    return `<div class="demo-panel"><h4>${escapeHtml(title)}</h4>${body}</div>`;
}

function kv(rows) {
    return `<dl class="demo-kv">${rows.map(([k, v]) =>
        `<dt>${escapeHtml(k)}</dt><dd>${v}</dd>`
    ).join('')}</dl>`;
}

function checkRow(label, check) {
    const icon = check.passed ? '✓' : '✗';
    const cls = check.passed ? 'pass' : 'fail';
    return `<div class="demo-check ${cls}"><span class="demo-check-icon">${icon}</span>
        <div><strong>${escapeHtml(label)}</strong>
            <div class="demo-check-detail">expected <code>${escapeHtml(String(check.expected))}</code></div>
            <div class="demo-check-detail">received <code>${escapeHtml(String(check.received))}</code></div>
        </div></div>`;
}

function renderError(stepId, message) {
    setStatus(stepId, 'error', 'error');
    setOutput(stepId, `<div class="demo-error">${escapeHtml(message)}</div>`);
}

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------

document.querySelectorAll('.demo-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.demo-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.demo-flow').forEach(f => f.classList.remove('active'));
        tab.classList.add('active');
        const flow = tab.dataset.flow;
        document.getElementById(`flow-${flow}`).classList.add('active');
    });
});

// ---------------------------------------------------------------------------
// Registration walkthrough
// ---------------------------------------------------------------------------

let registrationOptions = null;
let registrationCredential = null;

document.querySelector('[data-action="reg-1"]').addEventListener('click', async (e) => {
    e.target.disabled = true;
    setStatus('reg-1', 'active', 'running…');
    try {
        const res = await fetch('/demo/register/options', { method: 'POST' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'failed');

        registrationOptions = data.options;
        const b = data.breakdown;

        setOutput('reg-1', [
            panel('Challenge (32 random bytes)',
                kv([
                    ['purpose', escapeHtml(b.challenge.purpose)],
                    ['hex', `<code>${escapeHtml(b.challenge.rawHex)}</code>`],
                    ['base64url', `<code>${escapeHtml(b.challenge.rawBase64url)}</code>`],
                    ['length', `${b.challenge.length} bytes`],
                ])
            ),
            panel('User handle',
                kv([
                    ['purpose', escapeHtml(b.userId.purpose)],
                    ['hex', `<code>${escapeHtml(b.userId.rawHex)}</code>`],
                    ['base64url', `<code>${escapeHtml(b.userId.rawBase64url)}</code>`],
                ])
            ),
            panel('Relying Party ID',
                kv([
                    ['purpose', escapeHtml(b.rpId.purpose)],
                    ['value', `<code>${escapeHtml(b.rpId.value)}</code>`],
                ])
            ),
            panel('Accepted algorithms (pubKeyCredParams)',
                code(b.pubKeyCredParams.decoded)
            ),
            panel('Full PublicKeyCredentialCreationOptions sent to browser',
                code(data.options)
            ),
        ].join(''));

        setStatus('reg-1', 'done', 'done');
        unlockStep('reg-2');
    } catch (err) {
        renderError('reg-1', err.message);
        e.target.disabled = false;
    }
});

document.querySelector('[data-action="reg-2"]').addEventListener('click', async (e) => {
    if (!registrationOptions) return;
    e.target.disabled = true;
    setStatus('reg-2', 'active', 'waiting for authenticator…');

    // Convert base64url fields → ArrayBuffer for the WebAuthn API
    const opts = {
        ...registrationOptions,
        challenge: b64urlToBuffer(registrationOptions.challenge),
        user: { ...registrationOptions.user, id: b64urlToBuffer(registrationOptions.user.id) },
    };

    try {
        const credential = await navigator.credentials.create({ publicKey: opts });

        registrationCredential = {
            id: credential.id,
            type: credential.type,
            response: {
                clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
                attestationObject: bufferToB64url(credential.response.attestationObject),
            },
        };

        setOutput('reg-2', [
            panel('Raw PublicKeyCredential returned by the browser',
                kv([
                    ['id', `<code>${escapeHtml(credential.id)}</code>`],
                    ['type', `<code>${escapeHtml(credential.type)}</code>`],
                    ['response.clientDataJSON', `<code class="demo-trunc">${escapeHtml(registrationCredential.response.clientDataJSON)}</code>`],
                    ['response.attestationObject', `<code class="demo-trunc">${escapeHtml(registrationCredential.response.attestationObject)}</code>`],
                ])
            ),
            `<p class="demo-note">These ArrayBuffers are about to be POSTed to the server, which decodes the CBOR and verifies the credential. Continue to step 3.</p>`,
        ].join(''));

        setStatus('reg-2', 'done', 'done');
        unlockStep('reg-3');
    } catch (err) {
        renderError('reg-2', `${err.name || 'Error'}: ${err.message}`);
        e.target.disabled = false;
    }
});

document.querySelector('[data-action="reg-3"]').addEventListener('click', async (e) => {
    if (!registrationCredential) return;
    e.target.disabled = true;
    setStatus('reg-3', 'active', 'verifying…');

    try {
        const res = await fetch('/demo/register/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(registrationCredential),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'verification failed');

        const b = data.breakdown;
        const v = b.verificationChecks;

        setOutput('reg-3', [
            panel('Decoded clientDataJSON',
                `<p class="demo-note">${escapeHtml(b.clientDataJSON.purpose)}</p>` +
                code(b.clientDataJSON.decoded)
            ),
            panel('Decoded attestationObject (CBOR)',
                `<p class="demo-note">${escapeHtml(b.attestationObject.purpose)} (${b.attestationObject.rawLength} bytes)</p>` +
                code(b.attestationObject.decoded)
            ),
            panel('Extracted public key',
                `<p class="demo-note">${escapeHtml(b.extractedPublicKey.purpose)}</p>` +
                `<h5 class="demo-subhead">COSE_Key</h5>` + code(b.extractedPublicKey.cose) +
                `<h5 class="demo-subhead">PEM (SubjectPublicKeyInfo)</h5>` + code(b.extractedPublicKey.pem || '(unable to derive PEM)', 'pem')
            ),
            panel('Verification checks',
                checkRow('Challenge matches', v.challengeMatches) +
                checkRow('Type === "webauthn.create"', v.typeMatches) +
                checkRow('Origin matches', v.originMatches) +
                `<div class="demo-result ${data.verified ? 'pass' : 'fail'}">${escapeHtml(v.result)}</div>`
            ),
            `<p class="demo-note demo-ephemeral">${escapeHtml(b.ephemeralNote)}</p>`,
        ].join(''));

        setStatus('reg-3', data.verified ? 'done' : 'error', data.verified ? 'verified' : 'rejected');

        if (data.verified) {
            // Unlock the auth flow
            document.getElementById('auth-prereq').hidden = true;
            document.getElementById('auth-stepper').hidden = false;
        }
    } catch (err) {
        renderError('reg-3', err.message);
        e.target.disabled = false;
    }
});

// ---------------------------------------------------------------------------
// Authentication walkthrough
// ---------------------------------------------------------------------------

let authOptions = null;
let authAssertion = null;

document.querySelector('[data-action="auth-1"]').addEventListener('click', async (e) => {
    e.target.disabled = true;
    setStatus('auth-1', 'active', 'running…');
    try {
        const res = await fetch('/demo/auth/options', { method: 'POST' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'failed');

        authOptions = data.options;
        const b = data.breakdown;

        setOutput('auth-1', [
            panel('Fresh challenge',
                kv([
                    ['purpose', escapeHtml(b.challenge.purpose)],
                    ['hex', `<code>${escapeHtml(b.challenge.rawHex)}</code>`],
                    ['base64url', `<code>${escapeHtml(b.challenge.rawBase64url)}</code>`],
                ])
            ),
            panel('Relying Party ID',
                kv([
                    ['purpose', escapeHtml(b.rpId.purpose)],
                    ['value', `<code>${escapeHtml(b.rpId.value)}</code>`],
                ])
            ),
            panel('allowCredentials',
                `<p class="demo-note">${escapeHtml(b.allowCredentials.purpose)}</p>` +
                code(b.allowCredentials.credentialIds)
            ),
            panel('Full PublicKeyCredentialRequestOptions sent to browser',
                code(data.options)
            ),
        ].join(''));

        setStatus('auth-1', 'done', 'done');
        unlockStep('auth-2');
    } catch (err) {
        renderError('auth-1', err.message);
        e.target.disabled = false;
    }
});

document.querySelector('[data-action="auth-2"]').addEventListener('click', async (e) => {
    if (!authOptions) return;
    e.target.disabled = true;
    setStatus('auth-2', 'active', 'waiting for authenticator…');

    const opts = {
        ...authOptions,
        challenge: b64urlToBuffer(authOptions.challenge),
        allowCredentials: (authOptions.allowCredentials || []).map(c => ({
            ...c,
            id: b64urlToBuffer(c.id),
        })),
    };

    try {
        const assertion = await navigator.credentials.get({ publicKey: opts });

        authAssertion = {
            id: assertion.id,
            type: assertion.type,
            response: {
                clientDataJSON: bufferToB64url(assertion.response.clientDataJSON),
                authenticatorData: bufferToB64url(assertion.response.authenticatorData),
                signature: bufferToB64url(assertion.response.signature),
            },
        };

        setOutput('auth-2', [
            panel('Raw PublicKeyCredential (assertion) returned by the browser',
                kv([
                    ['id', `<code>${escapeHtml(assertion.id)}</code>`],
                    ['type', `<code>${escapeHtml(assertion.type)}</code>`],
                    ['response.clientDataJSON', `<code class="demo-trunc">${escapeHtml(authAssertion.response.clientDataJSON)}</code>`],
                    ['response.authenticatorData', `<code class="demo-trunc">${escapeHtml(authAssertion.response.authenticatorData)}</code>`],
                    ['response.signature', `<code class="demo-trunc">${escapeHtml(authAssertion.response.signature)}</code>`],
                ])
            ),
            `<p class="demo-note">The signature was produced inside the authenticator. The private key never enters the browser, the OS, or this page. Continue to step 3 to see the server verify it.</p>`,
        ].join(''));

        setStatus('auth-2', 'done', 'done');
        unlockStep('auth-3');
    } catch (err) {
        renderError('auth-2', `${err.name || 'Error'}: ${err.message}`);
        e.target.disabled = false;
    }
});

document.querySelector('[data-action="auth-3"]').addEventListener('click', async (e) => {
    if (!authAssertion) return;
    e.target.disabled = true;
    setStatus('auth-3', 'active', 'verifying…');

    try {
        const res = await fetch('/demo/auth/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(authAssertion),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'verification failed');

        const b = data.breakdown;
        const v = b.verificationChecks;

        setOutput('auth-3', [
            panel('Decoded clientDataJSON',
                `<p class="demo-note">${escapeHtml(b.clientDataJSON.purpose)}</p>` +
                code(b.clientDataJSON.decoded)
            ),
            panel('Decoded authenticatorData',
                `<p class="demo-note">${escapeHtml(b.authenticatorData.purpose)} (${b.authenticatorData.rawLength} bytes)</p>` +
                code(b.authenticatorData.decoded)
            ),
            panel('Signature',
                `<p class="demo-note">${escapeHtml(b.signature.purpose)}</p>` +
                kv([
                    ['length', `${b.signature.length} bytes`],
                    ['hex', `<code class="demo-trunc">${escapeHtml(b.signature.rawHex)}</code>`],
                ])
            ),
            panel('Signed payload',
                `<p class="demo-note">${escapeHtml(b.signedData.purpose)}</p>` +
                kv([
                    ['SHA-256(clientDataJSON)', `<code>${escapeHtml(b.signedData.clientDataHashHex)}</code>`],
                    ['total length', `${b.signedData.totalLength} bytes`],
                ])
            ),
            panel('Verification checks',
                checkRow('Challenge matches', v.challengeMatches) +
                checkRow('Type === "webauthn.get"', v.typeMatches) +
                `<div class="demo-check ${v.signatureValid.passed ? 'pass' : 'fail'}">
                    <span class="demo-check-icon">${v.signatureValid.passed ? '✓' : '✗'}</span>
                    <div><strong>Signature valid</strong>
                        <div class="demo-check-detail">algorithm: <code>${escapeHtml(v.signatureValid.algorithm)}</code></div>
                    </div>
                </div>` +
                `<div class="demo-result ${data.verified ? 'pass' : 'fail'}">${escapeHtml(v.result)}</div>`
            ),
        ].join(''));

        setStatus('auth-3', data.verified ? 'done' : 'error', data.verified ? 'verified' : 'rejected');
    } catch (err) {
        renderError('auth-3', err.message);
        e.target.disabled = false;
    }
});

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

document.getElementById('demo-reset').addEventListener('click', async () => {
    await fetch('/demo/reset', { method: 'POST' });
    location.reload();
});
