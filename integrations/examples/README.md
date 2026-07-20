# Vexyl Guard Integration Examples

These examples show where an application can call the local Vexyl Guard decision
gateway before retrieved content enters model context or an authorized MCP tool
runs. They use short defensive summaries, keyed local hashes, static tool policy,
and synthetic identifiers. They do not submit raw prompts, documents, tool
arguments, credentials, or request bodies.

The examples are reference applications, not internet-facing services. Both HTTP
servers bind to `127.0.0.1` by default. Put authentication and your own trusted
application policy in front of any adapted production route.

## Prerequisites

- Vexyl Guard installed with the local AI decision gateway enabled.
- Python 3.10 or newer for the FastAPI example.
- Node.js 20 or newer for the Express example.
- Access to the gateway socket and token through a trusted application account.

Packages leave the gateway disabled. Enable it only on a host that needs the local
decision boundary:

```bash
sudo systemctl enable --now vexyl-ai-gateway
sudo vexyl gateway health
sudo usermod -aG vexyl my-ai-service
```

Restart the application service after changing group membership. Do not grant the
`vexyl` group to model sandboxes, tool subprocesses, or untrusted workloads.

## FastAPI

From a source checkout:

```bash
cd integrations/examples/python
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
export PYTHONPATH="$(git rev-parse --show-toplevel)"
export VEXYL_EXAMPLE_IDENTIFIER_KEY="$(openssl rand -hex 32)"
uvicorn fastapi_app:create_app --factory --host 127.0.0.1 --port 8090
```

The app adds `VexylASGIMiddleware` and checks fixed, synthetic RAG metadata at the
point where content would be admitted. It deliberately has no request-body model
and never calls `request.body()`.

## Express

From a source checkout:

```bash
cd integrations/examples/node
npm ci --ignore-scripts
export VEXYL_EXAMPLE_IDENTIFIER_KEY="$(openssl rand -hex 32)"
npm start
```

The app uses Express 5, disables `X-Powered-By`, installs the Vexyl policy error
handler after its routes, and does not install a body parser.

## Exercise The Routes

```bash
curl -i http://127.0.0.1:8090/healthz
curl -i -X POST http://127.0.0.1:8090/demo/rag/allow
curl -i -X POST http://127.0.0.1:8090/demo/rag/block
```

Use port `8091` for the Express example. The allow route returns an admitted
context with policy code `0`. The block route returns a bounded `403` response when
the gateway assigns policy code `4`; it does not return rule details or raw input.

## Package-Installed Copies

Debian and RPM packages install read-only examples under:

```text
/usr/share/vexyl/integrations/examples
```

Copy the complete integrations tree to an application-owned working directory so
the Node examples retain their relative imports, then install example dependencies:

```bash
cp -a /usr/share/vexyl/integrations "$HOME/vexyl-guard-integrations"
cd "$HOME/vexyl-guard-integrations/examples/node"
npm ci --ignore-scripts
```

For the packaged Python modules, set `PYTHONPATH=/opt/vexyl`. The packaged Node
examples resolve the dependency-free Vexyl client from
the copied `integrations/node` directory.

## Compatibility Checks

The dependency-free harness starts a temporary authenticated gateway and evaluates
the same synthetic scenarios through both clients:

```bash
python3 -m tests.run_example_compatibility
```

After installing the example dependencies, run the HTTP contracts:

```bash
python3 -m unittest tests/test_example_apps.py -v
node tests/test_express_example.mjs
```

The tests assert matching policy outcomes, fail-closed responses, rejected MCP
control characters, absent raw identifiers, and no request-body forwarding. The
fixture file contains defensive summaries only and no runnable attack payloads.

## Production Adaptation

- Build security summaries in trusted application code.
- Hash local identifiers with stable private key material kept outside source.
- Keep allowlists, user scope, tool policy, approval state, and budgets static or
  independently authenticated.
- Call the guard immediately before content admission, memory persistence, model
  invocation, or tool execution.
- Treat gateway errors and policy codes `3` and `4` as a stopped sensitive action.
- Never copy authorization metadata from a prompt, retrieved document, model
  output, tool result, or inter-agent message.

The framework contract is documented in
[`docs/security/framework-integrations.md`](../../docs/security/framework-integrations.md).
