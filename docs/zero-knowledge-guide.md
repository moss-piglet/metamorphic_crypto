# Building Zero-Knowledge Phoenix Apps

A practical guide to implementing full client-side zero-knowledge encryption in a
Phoenix LiveView application using `metamorphic_crypto` and the `metamorphic-crypto`
Rust core compiled to WASM.

This guide walks through how [Metamorphic](https://metamorphic.app) implements its
encryption architecture — the same pattern you can use in your own app.

## What You'll Build

By the end of this guide you'll have:

- **Client-side encryption** — user data encrypted in the browser before it reaches
  your server
- **A key hierarchy** — each resource gets its own symmetric key, sealed to the
  user's public key
- **Searchable encrypted fields** — HMAC blind indexes for email lookups and
  uniqueness checks
- **Key distribution** — share access to encrypted resources between users without
  the server seeing plaintext
- **Defense in depth** — Cloak wrapping the already-encrypted blobs at rest

## How the Two Libraries Fit Together

```
                      metamorphic-crypto (Rust crate)
                      ┌──────────────────────────────┐
                      │  XSalsa20-Poly1305           │
                      │  X25519 box_seal             │
                      │  ML-KEM-768 + X25519 hybrid  │
                      │  Argon2id KDF                │
                      │  Recovery keys               │
                      └──────────┬───────────────────┘
                                 │
                ┌────────────────┼────────────────┐
                │                │                │
         Compiles to        Compiles to       Compiles to
           WASM                NIF               UniFFI
        (browser)          (Elixir/OTP)      (iOS/Android)
                │                │
                ▼                ▼
    Colocated JS hook     metamorphic_crypto
    (encrypts/decrypts    Hex package
     user data)           (key distribution,
                          re-keying, provisioning)
```

The same Rust code produces identical ciphertext regardless of which target it's
compiled to. Data sealed by the server NIF can be unsealed by the browser WASM
module, and vice versa.

## Key Architecture

```
Password (entered by user, never stored)
  │
  ├── Argon2id KDF ──► session_key (derived in browser at login)
  │                       │
  │                       └── decrypts private_key (secretbox)
  │
  ├── crypto_box_keypair ──► keypair
  │                            │
  │                            ├── public_key → stored on server
  │                            │
  │                            └── private_key → encrypted with session_key
  │                                                stored on server
  │
  └── ml_kem768_x25519.keygen ──► hybrid PQ keypair (optional)
                                     │
                                     ├── pq_public_key → stored on server
                                     │
                                     └── pq_private_key → encrypted with session_key
                                                           stored on server
```

### Context Keys

Each resource gets its own random symmetric key, called a **context key**:

```
user_key (random 32 bytes)
  ├── Encrypts: personal data (email, preferences)
  └── Distributed: seal_for_user(user_key, public_key)
     stored as user.encrypted_user_key

habit_key (random 32 bytes, per habit)
  ├── Encrypts: habit name, description, check-ins
  └── Distributed: seal_for_user(habit_key, public_key)
     stored as user_habits.encrypted_key

group_key (random 32 bytes, per group)
  ├── Encrypts: shared goals, check-ins
  └── Distributed to each member: seal_for_user(group_key, member.public_key)
```

### What Each Layer Handles

| Layer | Role | Technology |
|-------|------|------------|
| **Browser** | Encrypts/decrypts user data | WASM (`metamorphic-crypto` in JS hook) |
| **Browser** | Derives session key from password | WASM Argon2id |
| **Browser** | Seals context keys for sharing | WASM (client-side key distribution) |
| **Browser** | Caches derived keys | IndexedDB + Web Crypto API |
| **Server** | Generates keypairs during provisioning | `metamorphic_crypto` NIF |
| **Server** | Orchestrates key distribution events | LiveView `push_event` |
| **Server** | Background re-keying (PQ migration) | `metamorphic_crypto` NIF (with client-provided keys) |
| **Server** | Stores opaque ciphertext | Ecto schema |
| **Server** | Defense-in-depth at-rest encryption | Cloak (AES-256-GCM) |
| **Server** | Blind indexes for lookups | HMAC-SHA512 |

## Prerequisites

Add these to your `mix.exs`:

```elixir
def deps do
  [
    {:metamorphic_crypto, "~> 0.1"},
    {:cloak_ecto, "~> 1.3"},
    {:argon2_elixir, "~> 4.0"}   # for password hashing
  ]
end
```

The `metamorphic-crypto` WASM module needs to be in your `assets/vendor/` directory.
See the [Client Setup](#client-setup) section below.

## Client Setup

### 1. Add the WASM Module

Build the `metamorphic-crypto` Rust crate to WASM, or download the prebuilt module:

```bash
# From the metamorphic-crypto repo
wasm-pack build --target web --out-dir pkg
```

Copy the generated files to your Phoenix app:

```bash
cp pkg/metamorphic_crypto.js assets/vendor/metamorphic-crypto/
cp pkg/metamorphic_crypto_bg.wasm assets/vendor/metamorphic-crypto/
cp pkg/metamorphic_crypto.d.ts assets/vendor/metamorphic-crypto/
```

Then in `assets/js/app.js`, import and configure esbuild to serve the WASM:

```javascript
// assets/js/app.js
import { wasmInit } from "../vendor/metamorphic-crypto/metamorphic_crypto";
```

And ensure your WASM binary is served from the `/wasm/` path in your endpoint:

```elixir
# lib/my_app_web/endpoint.ex
plug Plug.Static,
  at: "/wasm",
  from: {:my_app, "priv/static/wasm"},
  gzip: false
```

### 2. Create the Crypto Module

```javascript
// assets/js/crypto/nacl.js

import { wasmInit } from "../../vendor/metamorphic-crypto/metamorphic_crypto";

let ready = false;
const readyQueue = [];

export function ensureReady() {
  if (ready) return Promise.resolve();
  return new Promise((resolve) => readyQueue.push(resolve));
}

export async function loadCrypto() {
  if (ready) return;
  const mod = await wasmInit("/wasm/metamorphic_crypto_bg.wasm");
  window.__metamorphic_crypto = mod;
  ready = true;
  readyQueue.forEach((fn) => fn());
}

export function generateKey() {
  return window.__metamorphic_crypto.generateKey();
}

export function generateKeypair() {
  return window.__metamorphic_crypto.generateKeypair();
}

export function encrypt(plaintext, key) {
  return window.__metamorphic_crypto.encrypt(plaintext, key);
}

export function decrypt(ciphertext, key) {
  return window.__metamorphic_crypto.decrypt(ciphertext, key);
}

export function seal(plaintext, publicKey) {
  return window.__metamorphic_crypto.seal(plaintext, publicKey);
}

export function unseal(ciphertext, publicKey, privateKey) {
  return window.__metamorphic_crypto.unseal(ciphertext, publicKey, privateKey);
}

export function deriveSessionKey(password, salt) {
  return window.__metamorphic_crypto.deriveSessionKey(password, salt);
}
```

Call `loadCrypto()` when your page loads:

```javascript
// assets/js/app.js
import { loadCrypto } from "./crypto/nacl";

loadCrypto();
```

### 3. The Key Cache Module

```javascript
// assets/js/crypto/key_cache.js

const DB_NAME = "_my_app_crypto";
const STORE_NAME = "keys";
const LS_CACHE_KEY = "_my_app_key_cache";

function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function cacheKeys(sessionKey, privateKey, userKey) {
  const db = await openDB();
  const tx = db.transaction(STORE_NAME, "readwrite");
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  tx.objectStore(STORE_NAME).put(key, "wrapping_key");

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(
    JSON.stringify({ sessionKey, privateKey, userKey, cachedAt: Date.now() })
  );
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
  localStorage.setItem(LS_CACHE_KEY, JSON.stringify({
    iv: Array.from(iv),
    ct: Array.from(new Uint8Array(encrypted))
  }));
}

export async function getCachedKeys() {
  const raw = localStorage.getItem(LS_CACHE_KEY);
  if (!raw) return null;

  const db = await openDB();
  const tx = db.transaction(STORE_NAME, "readonly");
  const key = await new Promise((resolve) => {
    const req = tx.objectStore(STORE_NAME).get("wrapping_key");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => resolve(null);
  });
  if (!key) return null;

  const { iv, ct } = JSON.parse(raw);
  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      key,
      new Uint8Array(ct)
    );
    return JSON.parse(new TextDecoder().decode(decrypted));
  } catch {
    return null;
  }
}

export function clearKeyCache() {
  localStorage.removeItem(LS_CACHE_KEY);
  const req = indexedDB.deleteDatabase(DB_NAME);
}
```

## Step 1: Registration Flow

The registration flow generates keys client-side before the form is submitted,
then sends the encrypted blobs to the server.

### Colocated Hook

```heex
<%!-- lib/my_app_web/live/registration_live.html.heex --%>
<.form for={@form} id="registration-form" phx-hook=".RegistrationHook">
  <.input field={@form[:email]} type="email" />
  <.input field={@form[:password]} type="password" />
  <.input field={@form[:encrypted_email]} type="hidden" name="user[encrypted_email]" />
  <.input field={@form[:public_key]} type="hidden" name="user[public_key]" />
  <.input field={@form[:encrypted_private_key]} type="hidden" name="user[encrypted_private_key]" />
  <.input field={@form[:encrypted_user_key]} type="hidden" name="user[encrypted_user_key]" />
  <.input field={@form[:key_hash]} type="hidden" name="user[key_hash]" />
  <button type="submit">
    Create Account
  </button>
</.form>

<script :type={Phoenix.LiveView.ColocatedHook} name=".RegistrationHook">
  import { ensureReady, generateKey, generateKeypair, seal, deriveSessionKey, encrypt } from "../../js/crypto/nacl";

  export default {
    mounted() {
      this.el.addEventListener("submit", async (e) => {
        e.preventDefault();
        await ensureReady();

        const password = this.el.querySelector('input[name="user[password]"]').value;
        const email = this.el.querySelector('input[name="user[email]"]').value;

        // 1. Derive session key
        const salt = window.__metamorphic_crypto.generateSalt();
        const sessionKey = await deriveSessionKey(password, salt);

        // 2. Generate keypair
        const keypair = generateKeypair();
        const encryptedPrivateKey = encrypt(keypair.secretKey, sessionKey);

        // 3. Generate user_key (top-level context key)
        const userKey = generateKey();
        const encryptedUserKey = seal(userKey, keypair.publicKey);

        // 4. Encrypt email
        const encryptedEmail = encrypt(email, userKey);

        // 5. Store session key temporarily — SessionKeyDeriver will pick
        //    this up on the next page load to derive all keys
        sessionStorage.setItem("_session_key_temp", sessionKey);

        // 6. Inject hidden fields (salt is already Base64 from the WASM module)
        this.el.querySelector('input[name="user[key_hash]"]').value = salt + "$argon2id";
        this.el.querySelector('input[name="user[public_key]"]').value = keypair.publicKey;
        this.el.querySelector('input[name="user[encrypted_private_key]"]').value = encryptedPrivateKey;
        this.el.querySelector('input[name="user[encrypted_user_key]"]').value = encryptedUserKey;
        this.el.querySelector('input[name="user[encrypted_email]"]').value = encryptedEmail;

        // 7. Submit the form — server stores blobs, redirects to dashboard,
        //    where SessionKeyDeriver uses the temp key to derive everything
        this.el.submit();
      });
    }
  }
</script>
```

### Server-Side Controller

On the server, receive the encrypted blobs and store them.

**Important trade-off:** The server sees the plaintext email and password
transiently during registration. The password is needed for server-side Argon2
session auth. The email is needed to send the confirmation email and compute the
HMAC blind index. After the request completes, neither is persisted — only the
`email_hash` (HMAC) and `encrypted_email` (ciphertext) remain in the database.
Declare the `email` field as virtual with `redact: true` to prevent accidental
persistence or logging.

```elixir
defmodule MyAppWeb.UserRegistrationController do
  use MyAppWeb, :controller

  alias MyApp.Accounts
  alias MyApp.Accounts.User

  def create(conn, %{"user" => user_params}) do
    # Extract transient plaintext email for confirmation email and blind index
    plain_email = user_params["email"]

    # Compute HMAC blind index for lookups
    email_hash = :crypto.mac(:hmac, :sha512, Application.fetch_env!(:my_app, :email_hmac_key), String.downcase(plain_email))

    # Hash password for server-side auth (independent of client-side KDF).
    # The client derives session_key via Argon2id with its own salt for key
    # derivation. The server hashes the password with a separate Argon2 salt
    # for session authentication. These are two separate operations serving
    # different purposes — they never share a salt.
    hashed_password = Argon2.hash_pwd_salt(user_params["password"])

    attrs = %{
      email_hash: email_hash,
      encrypted_email: user_params["encrypted_email"],
      public_key: user_params["public_key"],
      encrypted_private_key: user_params["encrypted_private_key"],
      encrypted_user_key: user_params["encrypted_user_key"],
      key_hash: user_params["key_hash"],
      hashed_password: hashed_password
    }

    case Accounts.create_user(attrs) do
      {:ok, user} ->
        # Send confirmation email using transient plaintext
        MyApp.Email.confirm_email(plain_email, user)
          |> MyApp.Mailer.deliver_later()

        conn
        |> put_flash(:info, "Account created")
        |> redirect(to: ~p"/dashboard")

      {:error, changeset} ->
        render(conn, :new, changeset: changeset)
    end
  end
end
```

### Ecto Schema

Store the encrypted blobs and use Cloak encrypted types for at-rest protection:

```elixir
defmodule MyApp.Accounts.User do
  use Ecto.Schema

  schema "users" do
    field :email_hash, :binary                       # HMAC-SHA512 blind index
    field :encrypted_email, MyApp.Encrypted.Binary   # E2E encrypted email (Cloak-wrapped)
    field :public_key, MyApp.Encrypted.Binary        # X25519 public key (Cloak-wrapped)
    field :encrypted_private_key, MyApp.Encrypted.Binary  # X25519 private key (Cloak-wrapped)
    field :encrypted_user_key, MyApp.Encrypted.Binary     # user_key sealed for this user
    field :key_hash, :string                              # Argon2id salt + params
    field :hashed_password, :string                       # Argon2 password hash (server auth)

    # Optional: post-quantum hybrid keypair
    field :pq_public_key, MyApp.Encrypted.Binary
    field :encrypted_pq_private_key, MyApp.Encrypted.Binary

    timestamps()
  end
end
```

**Note:** The `encrypted_private_key` field is encrypted twice — once by the
client (secretbox with session key) and once by Cloak (AES-256-GCM at rest).
The server cannot read the inner layer. This is defense-in-depth.

## Step 2: Login Flow

### Hook to Derive Keys Before Auth

```heex
<%!-- lib/my_app_web/live/login_live.html.heex --%>
<.form for={@form} id="login-form" phx-hook=".LoginHook">
  <.input field={@form[:email]} type="email" />
  <.input field={@form[:password]} type="password" />
  <button type="submit">Sign In</button>
</.form>
```

On login, the hook intercepts the form to:
1. Request the user's `key_hash` (containing the Argon2id salt)
2. Derive the session key
3. Store the session key temporarily
4. Submit the form normally for server auth

```javascript
<script :type={Phoenix.LiveView.ColocatedHook} name=".LoginHook">
  import { ensureReady, deriveSessionKey } from "../../js/crypto/nacl";

  export default {
    mounted() {
      this.el.addEventListener("submit", async (e) => {
        e.preventDefault();
        await ensureReady();

        const email = this.el.querySelector('input[name="user[email]"]').value;
        const password = this.el.querySelector('input[name="user[password]"]').value;

        // 1. Fetch key_hash (contains salt)
        const resp = await fetch("/api/auth/salt", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email })
        });
        const { key_hash } = await resp.json();

        // 2. Derive session key from salt + password
        const salt = key_hash.split("$")[0];
        const sessionKey = await deriveSessionKey(password, salt);

        // 3. Store temporarily in sessionStorage
        sessionStorage.setItem("_session_key_temp", sessionKey);

        // 4. Submit original form for password verification
        this.el.submit();
      });
    }
  }
</script>
```

### The Salt Endpoint (Server)

This endpoint returns the Argon2id salt for a given email. It must be hardened
against user enumeration:

- **Timing normalization** — enforce a minimum response time so an attacker
  can't distinguish "user exists" (DB hit) from "user not found" (fake hash).
- **Rate limiting** — 10 requests/minute per IP.
- **Deterministic fake salt** — for unknown emails, derive a fake salt from a
  server secret + the email (HMAC). This makes repeated requests for the same
  unknown email return the same hash, preventing timing-based enumeration.

```elixir
defmodule MyAppWeb.AuthSaltController do
  use MyAppWeb, :controller

  alias MyApp.Accounts

  @min_response_ms 100

  def show(conn, %{"email" => email}) when is_binary(email) and email != "" do
    start = System.monotonic_time(:millisecond)

    email_hash =
      :crypto.mac(:hmac, :sha512,
        Application.fetch_env!(:my_app, :email_hmac_key),
        String.downcase(email))

    key_hash =
      case Repo.get_by(User, email_hash: email_hash) do
        %User{key_hash: kh} -> kh
        nil -> generate_fake_key_hash(email)
      end

    enforce_min_duration(start)
    json(conn, %{key_hash: key_hash})
  end

  def show(conn, _params) do
    conn |> put_status(:bad_request) |> json(%{error: "email is required"})
  end

  # Deterministic fake salt — same email always produces the same fake,
  # so timing is consistent regardless of how many times it's queried
  defp generate_fake_key_hash(email) do
    fake_salt =
      :crypto.mac(:hmac, :sha512,
        Application.fetch_env!(:my_app, :fake_salt_secret),
        String.downcase(email))
      |> binary_part(0, 16)
      |> Base.encode64()

    fake_salt <> "$argon2id"
  end

  defp enforce_min_duration(start) do
    elapsed = System.monotonic_time(:millisecond) - start
    remaining = @min_response_ms - elapsed
    if remaining > 0, do: Process.sleep(remaining)
  end
end
```

In the router, apply rate limiting:

```elixir
# lib/my_app_web/router.ex
pipeline :api_rate_limited do
  plug :accepts, ["json"]
  plug MyAppWeb.Plugs.RateLimiter, scale: :timer.minutes(1), limit: 10, key_prefix: "api"
end

scope "/api", MyAppWeb do
  pipe_through :api_rate_limited
  post "/auth/salt", AuthSaltController, :show
end
```

## Step 3: Key Derivation on Dashboard Mount

After login or registration, the user is redirected to an authenticated page.
The `SessionKeyDeriver` hook picks up the temporary session key (stored in
sessionStorage by the Login/Registration hook) and derives the full key set.

### Storage Model

Keys live in two layers:

| Layer | Scope | Purpose |
|-------|-------|---------|
| **sessionStorage** | Current tab only | Active decryption keys — cleared on tab close |
| **localStorage + IndexedDB** | Persistent | Encrypted key cache — survives browser restarts |

This is a UX vs. security trade-off:

- **sessionStorage only** — most secure. User must re-enter password on every
  tab close. Appropriate for high-security contexts.
- **Persistent cache** — better UX. Derived keys are encrypted with a
  non-extractable AES-256-GCM wrapping key (IndexedDB) and stored as ciphertext
  (localStorage). Survives browser restarts without password re-entry.

In Metamorphic, we use **both**: sessionStorage for the active tab, and an
encrypted persistent cache so users don't have to re-enter their password on
browser restart. The persistent cache is cleared on logout and password change.

### Data Attributes

Pass the encrypted keys from the server to the client via data attributes:

```heex
<%!-- In your Layouts.app template --%>
<div
  id="session-key-deriver"
  phx-hook=".SessionKeyDeriver"
  phx-update="ignore"
  data-key-hash={@current_scope.user.key_hash}
  data-public-key={@current_scope.user.public_key}
  data-encrypted-private-key={@current_scope.user.encrypted_private_key}
  data-encrypted-user-key={@current_scope.user.encrypted_user_key}
>
</div>
```

### The SessionKeyDeriver Hook

```javascript
<script :type={Phoenix.LiveView.ColocatedHook} name=".SessionKeyDeriver">
  import { ensureReady, decrypt, unseal } from "../../js/crypto/nacl";
  import { cacheKeys, getCachedKeys } from "../../js/crypto/key_cache";

  export default {
    async mounted() {
      await ensureReady();

      const el = this.el;
      const publicKey = el.dataset.publicKey;
      const encryptedPrivateKey = el.dataset.encryptedPrivateKey;
      const encryptedUserKey = el.dataset.encryptedUserKey;

      // Always store public key — it's not secret and other hooks need it
      sessionStorage.setItem("_public_key", publicKey);

      // 1. Check sessionStorage — already derived this session?
      const existingKey = sessionStorage.getItem("_session_key");
      if (existingKey) {
        // Validate by trial-decrypting the private key
        try {
          decrypt(encryptedPrivateKey, existingKey);
          return; // Keys are valid
        } catch {
          // Stale keys (password changed) — fall through
        }
      }

      // 2. Check persistent cache (encrypted localStorage + IndexedDB)
      const cached = await getCachedKeys();
      if (cached) {
        try {
          decrypt(encryptedPrivateKey, cached.sessionKey);
          sessionStorage.setItem("_session_key", cached.sessionKey);
          sessionStorage.setItem("_private_key", cached.privateKey);
          sessionStorage.setItem("_user_key", cached.userKey);
          return;
        } catch {
          // Cache is stale — fall through
        }
      }

      // 3. Derive from temp key (just logged in or registered)
      const tempKey = sessionStorage.getItem("_session_key_temp");
      if (!tempKey) {
        window.location = "/users/reauthenticate";
        return;
      }

      // Decrypt private key with session key
      const privateKey = decrypt(encryptedPrivateKey, tempKey);

      // Unseal user_key with keypair
      const userKey = unseal(encryptedUserKey, publicKey, privateKey);

      // Store in sessionStorage for this tab
      sessionStorage.setItem("_session_key", tempKey);
      sessionStorage.setItem("_private_key", privateKey);
      sessionStorage.setItem("_user_key", userKey);
      sessionStorage.removeItem("_session_key_temp");

      // Cache for browser restart (encrypted with Web Crypto)
      await cacheKeys(tempKey, privateKey, userKey);
    }
  }
</script>
```

## Step 4: Encrypting Resources

Here's how to encrypt a habit (or any resource) before it reaches the server.
The pattern: intercept the form, encrypt client-side, push encrypted params via
LiveView event.

### Colocated Hook for Creating a Resource

The form uses a `type="button"` submit trigger (not `type="submit"`) so that
if the JS hook fails to load, the form **cannot submit unencrypted data** to
the server. Data is only sent via `pushEvent` after successful encryption.

```heex
<%!-- lib/my_app_web/live/habit_live/index.html.heex --%>
<div id="habit-form-wrapper" phx-hook=".HabitFormHook">
  <.input type="text" id="habit-name-input" name="name" label="Name" />
  <.input type="textarea" id="habit-desc-input" name="description" label="Description" />
  <button type="button" data-action="submit-habit"
    class="btn bg-primary text-primary-content">
    Create Habit
  </button>
</div>

<script :type={Phoenix.LiveView.ColocatedHook} name=".HabitFormHook">
  import { ensureReady, generateKey, seal, encrypt } from "../../js/crypto/nacl";

  export default {
    mounted() {
      const btn = this.el.querySelector('[data-action="submit-habit"]');

      btn.addEventListener("click", async () => {
        await ensureReady();

        const privateKey = sessionStorage.getItem("_private_key");
        const publicKey = sessionStorage.getItem("_public_key");
        if (!privateKey || !publicKey) {
          window.location = "/users/reauthenticate";
          return;
        }

        const name = this.el.querySelector("#habit-name-input").value;
        const description = this.el.querySelector("#habit-desc-input").value;

        try {
          // Generate a per-habit context key
          const habitKey = generateKey();

          // Encrypt the fields with the context key
          const encryptedName = encrypt(name, habitKey);
          const encryptedDescription = encrypt(description, habitKey);

          // Seal the context key to the user's public key
          const encryptedKey = seal(habitKey, publicKey);

          // Push encrypted params to the server via LiveView
          this.pushEvent("create_habit", {
            encrypted_name: encryptedName,
            encrypted_description: encryptedDescription,
            encrypted_key: encryptedKey,
          });
        } catch (err) {
          console.error("Encryption failed:", err);
        }
      });
    }
  }
</script>
```

### Server Handler

The server receives only encrypted blobs. It validates structure and stores them.

```elixir
defmodule MyAppWeb.HabitLive do
  use MyAppWeb, :live_view

  def handle_event("create_habit", params, socket) do
    %{"encrypted_name" => enc_name, "encrypted_description" => enc_desc,
      "encrypted_key" => enc_key} = params

    user = socket.assigns.current_scope.user

    case MyApp.Habits.create_habit(user, %{
      encrypted_name: enc_name,
      encrypted_description: enc_desc,
      encrypted_key: enc_key
    }) do
      {:ok, habit} ->
        {:noreply,
         socket
         |> put_flash(:info, "Habit created")
         |> stream_insert(:habits, habit)}

      {:error, changeset} ->
        {:noreply, assign(socket, form: to_form(changeset))}
    end
  end
end
```

### Context Module

```elixir
defmodule MyApp.Habits do
  alias MyApp.Repo
  alias MyApp.Habits.{Habit, UserHabit}

  def create_habit(user, attrs) do
    Ecto.Multi.new()
    |> Ecto.Multi.insert(:habit, %Habit{
      user_id: user.id,
      encrypted_name: attrs.encrypted_name,
      encrypted_description: attrs.encrypted_description
    })
    |> Ecto.Multi.insert(:user_habit, fn %{habit: habit} ->
      %UserHabit{
        user_id: user.id,
        habit_id: habit.id,
        encrypted_key: attrs.encrypted_key,
        role: "owner"
      }
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{habit: habit}} -> {:ok, habit}
      {:error, _, changeset, _} -> {:error, changeset}
    end
  end
end
```

### Ecto Schema for Encrypted Resources

```elixir
defmodule MyApp.Habits.Habit do
  use Ecto.Schema

  schema "habits" do
    field :encrypted_name, MyApp.Encrypted.Binary
    field :encrypted_description, MyApp.Encrypted.Binary

    belongs_to :user, MyApp.Accounts.User
    has_many :user_habits, MyApp.Habits.UserHabit
    timestamps()
  end
end

defmodule MyApp.Habits.UserHabit do
  use Ecto.Schema

  schema "user_habits" do
    field :encrypted_key, MyApp.Encrypted.Binary  # context key sealed for this user
    field :role, :string, default: "owner"

    belongs_to :user, MyApp.Accounts.User
    belongs_to :habit, MyApp.Habits.Habit
    timestamps()
  end
end
```

Where `MyApp.Encrypted.Binary` is your Cloak encrypted type (see [Cloak docs](https://hexdocs.pm/cloak_ecto/install.html)).

## Step 5: Key Distribution (Sharing Access)

When User A shares a resource with User B, someone needs to seal the context key
to User B's public key. In a true zero-knowledge architecture, **the server never
unseals or seals context keys** — it doesn't have anyone's private key.

Instead, key distribution is **event-driven and client-side**:

1. Server detects that a member needs a key (invited, pending access)
2. Server pushes a `push_event` to an online admin/owner's browser
3. The admin's client **unseals** the context key with their own private key
4. The admin's client **re-seals** it for the target user's public key
5. The admin's client pushes the sealed blob back to the server
6. Server stores it on the target user's join record

This means key distribution happens when an authorized user is online. The server
orchestrates — it knows *who* needs a key and *whose* public key to seal to — but
it never touches plaintext key material.

### Server: Detecting Pending Keys

```elixir
defmodule MyApp.Groups do
  import Ecto.Query

  def pending_key_requests(%Scope{user: user}) do
    # Find group members who've been invited but don't have a key yet
    from(gm in GroupMember,
      join: g in assoc(gm, :group),
      join: u in assoc(gm, :user),
      join: admin_gm in GroupMember,
        on: admin_gm.group_id == g.id and admin_gm.user_id == ^user.id,
      where: is_nil(gm.encrypted_key),
      where: admin_gm.role in ["owner", "admin"],
      where: not is_nil(u.public_key),
      select: %{
        group_id: g.id,
        member_user_id: u.id,
        member_public_key: u.public_key,
        member_pq_public_key: u.pq_public_key,
        admin_encrypted_key: admin_gm.encrypted_key
      }
    )
    |> Repo.all()
  end
end
```

### Server: Pushing to the Client

In your LiveView, on mount or when a new member is added:

```elixir
defmodule MyAppWeb.GroupsLive do
  use MyAppWeb, :live_view

  def mount(_params, _session, socket) do
    pending = MyApp.Groups.pending_key_requests(socket.assigns.current_scope)

    socket =
      if pending != [] do
        push_event(socket, "distribute_keys", %{requests: pending})
      else
        socket
      end

    {:ok, socket}
  end

  # Client sends back the sealed key
  def handle_event("key_distributed", params, socket) do
    %{"group_id" => group_id, "member_user_id" => member_user_id,
      "encrypted_key" => encrypted_key} = params

    # Validate: only admins can distribute, and blob must be well-formed base64
    with :ok <- validate_admin(socket, group_id),
         :ok <- validate_encrypted_key(encrypted_key) do
      MyApp.Groups.store_distributed_key(group_id, member_user_id, encrypted_key)
    end

    {:noreply, socket}
  end

  defp validate_encrypted_key(key) when is_binary(key) and byte_size(key) > 0 do
    # Minimum 80 bytes: crypto_box_SEALBYTES (48) + 32-byte key = 80 for legacy box_seal.
    # Maximum 2048 bytes: covers hybrid PQ sealed keys (ML-KEM-768 ciphertext is ~1100 bytes).
    case Base.decode64(key) do
      {:ok, decoded} when byte_size(decoded) >= 80 and byte_size(decoded) <= 2048 -> :ok
      _ -> {:error, :invalid_encrypted_key}
    end
  end
end
```

### Client: The KeyDistributor Hook

This hook listens for `distribute_keys` events and does the cryptographic work:

```heex
<div id="key-distributor" phx-hook=".KeyDistributor" phx-update="ignore"></div>

<script :type={Phoenix.LiveView.ColocatedHook} name=".KeyDistributor">
  import { ensureReady, unseal, seal } from "../../js/crypto/nacl";

  export default {
    mounted() {
      this.handleEvent("distribute_keys", async ({ requests }) => {
        await ensureReady();

        const privateKey = sessionStorage.getItem("_private_key");
        const publicKey = sessionStorage.getItem("_public_key");
        if (!privateKey || !publicKey) return;

        for (const req of requests) {
          try {
            // 1. Unseal the context key using MY private key
            const contextKey = unseal(
              req.admin_encrypted_key, publicKey, privateKey
            );

            // 2. Re-seal it for the TARGET user's public key
            const sealedForMember = seal(contextKey, req.member_public_key);

            // 3. Send the sealed blob back to the server
            this.pushEvent("key_distributed", {
              group_id: req.group_id,
              member_user_id: req.member_user_id,
              encrypted_key: sealedForMember,
            });
          } catch (err) {
            console.error("Key distribution failed:", err);
          }
        }
      });
    }
  }
</script>
```

### When Can the Server Use MetamorphicCrypto for Key Distribution?

The server-side NIF is useful for key distribution in specific scenarios where
you intentionally grant the server temporary access to a context key:

- **Account provisioning** — generating keypairs and the initial `user_key` seal
  during registration (before the user has a client session)
- **Oban background jobs** — re-sealing context keys during a PQ migration where
  the server has been explicitly given a batch of plaintext context keys by the
  client for re-sealing
- **Admin-sealed resources** — if your app has a concept of "server-managed"
  resources that aren't zero-knowledge (e.g., system announcements encrypted for
  all users), the server can seal to each user's public key

For true zero-knowledge, the client always does the seal/unseal. The server
stores and routes opaque blobs.

## Step 6: Displaying Encrypted Data

When sending encrypted data to the client, pass the encrypted blobs and keys
as data attributes on the LiveView elements. The hook decrypts and updates the
DOM client-side.

```heex
<div id="habits" phx-update="stream">
  <div
    :for={{id, habit} <- @streams.habits}
    id={id}
    phx-hook=".HabitCard"
    data-encrypted-name={habit.encrypted_name}
    data-encrypted-description={habit.encrypted_description}
    data-encrypted-key={habit.user_habit.encrypted_key}
  >
    <h3 data-decrypt-name class="font-semibold text-base-content animate-pulse">···</h3>
    <p data-decrypt-description class="text-base-content/70 animate-pulse">···</p>
    <p data-decrypt-error class="text-error hidden"></p>
  </div>
</div>
```

The hook manages its own DOM after decryption, so content is only updated
client-side.

### The Decryption Hook

```heex
<script :type={Phoenix.LiveView.ColocatedHook} name=".HabitCard">
  import { ensureReady, decrypt, unseal } from "../../js/crypto/nacl";

  export default {
    async mounted() {
      await ensureReady();

      const privateKey = sessionStorage.getItem("_private_key");
      const publicKey = sessionStorage.getItem("_public_key");

      if (!privateKey || !publicKey) {
        window.location = "/users/reauthenticate";
        return;
      }

      const el = this.el;

      try {
        // Unseal the per-resource context key
        const habitKey = unseal(el.dataset.encryptedKey, publicKey, privateKey);

        // Decrypt the fields
        const name = decrypt(el.dataset.encryptedName, habitKey);
        const description = decrypt(el.dataset.encryptedDescription, habitKey);

        // Update the DOM — use textContent (NOT innerHTML) to prevent XSS.
        // Decrypted user content could contain <script> tags or event handlers.
        const nameEl = el.querySelector("[data-decrypt-name]");
        const descEl = el.querySelector("[data-decrypt-description]");
        if (nameEl) nameEl.textContent = name;
        if (descEl) descEl.textContent = description;
      } catch (err) {
        const errEl = el.querySelector("[data-decrypt-error]");
        if (errEl) errEl.textContent = "Failed to decrypt";
        console.error("Decryption failed:", err);
      }
    }
  }
</script>
```

## Schema Design Rules

1. **Encrypted fields are `:binary`** — always. The ciphertext is non-printable
   binary data.
2. **Context keys in join tables** — store the sealed context key on the join
   table (`user_habits.encrypted_key`), not the resource table.
3. **Blind indexes for lookups** — use HMAC-SHA512 for case-insensitive
   uniqueness checks (email, username).
4. **Metadata stays plaintext** — dates, positions, colors, and other non-sensitive
   data can remain in plaintext. Be deliberate about what's metadata vs. content.
5. **Cloak wraps everything** — every `:binary` encrypted field should be
   Cloak-encrypted at rest as a defense-in-depth layer.

## Full Example App

A complete, minimal Phoenix app demonstrating this architecture is available at
[github.com/moss-piglet/zk-phoenix-example](https://github.com/moss-piglet/zk-phoenix-example)
(coming soon).

## Security Considerations

### Password Never Reaches sessionStorage

Only the Argon2id-derived session key is stored. The raw password is used once
during KDF derivation and immediately discarded.

### Key Cache is Encrypted at Rest

The persistent key cache uses the Web Crypto API with a non-extractable AES-256-GCM
wrapping key stored in IndexedDB. An adversary who copies localStorage from disk
gets only encrypted ciphertext. The wrapping key cannot be extracted by JavaScript
— it can only be used for encrypt/decrypt operations via the Web Crypto API.

Clear the cache on logout and password change:

```javascript
function onLogout() {
  sessionStorage.clear();
  localStorage.removeItem("_my_app_key_cache");
  indexedDB.deleteDatabase("_my_app_crypto");
}
```

### Salt Endpoint is a User Enumeration Vector

The `/api/auth/salt` endpoint necessarily reveals whether an email exists (different
response for known vs. unknown users). Mitigate this with:

1. **Timing normalization** — enforce minimum response time (100ms+)
2. **Deterministic fake salts** — HMAC-derived, so repeated queries for the same
   unknown email return the same fake (no timing delta on cache hits)
3. **Rate limiting** — 10 requests/minute per IP minimum. Use IP hashing for
   privacy in logs.

### XSS is the Primary Threat to Key Material

During an active session, derived keys live in `sessionStorage`. Any XSS
vulnerability can read them. This is the weakest link in the architecture — not
the crypto, but the browser execution environment.

**Mitigations (all required for production):**

1. **Strict Content-Security-Policy** — per-request nonce for scripts, no
   `unsafe-inline` for script-src, `frame-ancestors 'none'`:

   ```elixir
   # lib/my_app_web/plugs/content_security_policy.ex
   defmodule MyAppWeb.Plugs.ContentSecurityPolicy do
     import Plug.Conn

     def init(opts), do: opts

     def call(conn, _opts) do
       nonce = Base.encode64(:crypto.strong_rand_bytes(16))

       conn
       |> assign(:csp_nonce, nonce)
       |> put_resp_header("content-security-policy", """
       default-src 'self'; \
       script-src 'self' 'nonce-#{nonce}' 'wasm-unsafe-eval'; \
       style-src 'self' 'unsafe-inline'; \
       img-src 'self' data:; \
       connect-src 'self'; \
       frame-ancestors 'none'; \
       object-src 'none'; \
       base-uri 'self'\
       """)
     end
   end
   ```

   Wire it into your browser pipeline:

   ```elixir
   pipeline :browser do
     # ...
     plug MyAppWeb.Plugs.ContentSecurityPolicy
   end
   ```

2. **No inline scripts** — use colocated hooks (which are bundled by esbuild)
   and nonce-tagged script tags only. Never use `<script>` without a nonce.

3. **Sanitize all user-generated content** — Phoenix's HEEx templates
   auto-escape by default, but be careful with `raw/1` and `Phoenix.HTML.raw/1`.

4. **HttpOnly session cookies** — Phoenix does this by default. The session
   token is never accessible to JavaScript.

The persistent key cache (IndexedDB + Web Crypto) is more resilient — the
wrapping key is non-extractable, so even XSS can't read raw key bytes from it.
But during an active session, `sessionStorage` is the attack surface.

### Plaintext Email Touches the Server at Registration

The server transiently sees the plaintext email during registration (for
confirmation email delivery and HMAC blind index computation). After the request
completes, only `email_hash` and `encrypted_email` persist. This is an
intentional trade-off — alternatives (like client-side HMAC) would require
shipping the HMAC secret to the browser, which is worse.

If you need stronger email privacy, you can skip email confirmation entirely
and only store the HMAC + encrypted blob. The user's email is then only ever
readable by the user themselves (via client-side decryption).

### Cloak is Defense-in-Depth, Not the Primary Protection

The primary encryption is client-side XSalsa20-Poly1305 / ML-KEM-768. The Cloak
layer protects against DB-level compromise but is not the user's E2E encryption.
If you rotate your Cloak key, user data is still protected by the E2E layer.

### Key Rotation is Not Built In

This library uses a single-key design per context. If you need key rotation
(multiple active keys with version-tagged ciphertext), use Cloak for the Ecto
layer. MetamorphicCrypto's server-side role is key distribution and generation,
not rotation.

### Key Distribution Requires an Online Admin

In the event-driven model, key distribution only happens when an authorized user
(admin/owner) is online. If no admin is online when a new member is invited, the
member gets their key the next time any admin loads the page. Design your UI to
show a "pending access" state for members awaiting keys.

## Reading

- [Metamorphic encryption architecture](https://github.com/moss-piglet/metamorphic/blob/main/docs/ENCRYPTION_ARCHITECTURE.md)
— the production reference implementation
- [What Post-Quantum Encryption Means for Your Data](https://dev.to/mosspiglet/what-post-quantum-encryption-means-for-your-data)
- [Cloak](https://hex.pm/packages/cloak) — Ecto encrypted types and key rotation
- [metamorphic-crypto](https://github.com/moss-piglet/metamorphic-crypto)
- [libsodium documentation](https://doc.libsodium.org/) — wire format reference
