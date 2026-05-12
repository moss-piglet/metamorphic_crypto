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
| **Browser** | Caches derived keys | IndexedDB + Web Crypto API |
| **Server** | Generates keypairs during provisioning | `metamorphic_crypto` NIF |
| **Server** | Seals context keys for key distribution | `metamorphic_crypto` NIF |
| **Server** | Background re-keying (PQ migration) | `metamorphic_crypto` NIF |
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

        // 5. Inject hidden fields
        this.el.querySelector('input[name="user[key_hash]"]').value =
          Array.from(salt).map(b => String.fromCharCode(b)).join('') + "$argon2id";
        this.el.querySelector('input[name="user[public_key]"]').value = keypair.publicKey;
        this.el.querySelector('input[name="user[encrypted_private_key]"]').value = encryptedPrivateKey;
        this.el.querySelector('input[name="user[encrypted_user_key]"]').value = encryptedUserKey;
        this.el.querySelector('input[name="user[encrypted_email]"]').value = encryptedEmail;

        // 6. Submit the form
        this.el.submit();
      });
    }
  }
</script>
```

### Server-Side Controller

On the server, receive the encrypted blobs and store them. The server never sees
the plaintext — it only stores opaque ciphertext.

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

    # Hash password for server-side auth
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

Store the encrypted blobs as `:binary` and use Cloak for at-rest protection:

```elixir
defmodule MyApp.Accounts.User do
  use Ecto.Schema
  use Cloak.Ecto.Schema, encrypted: [:encrypted_email, :encrypted_private_key,
                                      :encrypted_user_key]

  schema "users" do
    field :email_hash, :binary          # HMAC-SHA512 blind index
    field :encrypted_email, :binary     # E2E encrypted email
    field :public_key, :binary          # X25519 public key (Cloak)
    field :encrypted_private_key, :binary  # X25519 private key (Cloak + secretbox)
    field :encrypted_user_key, :binary     # user_key sealed for this user
    field :key_hash, :string               # Argon2id params for re-derivation
    field :hashed_password, :string        # Argon2 password hash (server auth)

    # Optional: post-quantum hybrid keypair
    field :pq_public_key, :binary
    field :encrypted_pq_private_key, :binary

    timestamps()
  end
end
```

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

```elixir
defmodule MyAppWeb.Api.AuthController do
  use MyAppWeb, :controller

  alias MyApp.Accounts

  def salt(conn, %{"email" => email}) do
    email_hash = :crypto.mac(:hmac, :sha512,
      Application.fetch_env!(:my_app, :email_hmac_key),
      String.downcase(email))

    user = Repo.get_by(User, email_hash: email_hash)

    key_hash = if user do
      user.key_hash
    else
      # Timing-normalized fake hash for unknown emails
      "AAAAAAAAAAAAAAAAAAAAAA$argon2id"
    end

    json(conn, %{key_hash: key_hash})
  end
end
```

## Step 3: Key Derivation on Dashboard Mount

After login, the user is redirected to the dashboard. Pass the encrypted keys
from the server to the client via data attributes:

```heex
<%!-- In your Layouts.app template --%>
<div
  id="session-key-deriver"
  phx-hook=".SessionKeyDeriver"
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
      // 1. Check sessionStorage (already derived this session)
      if (sessionStorage.getItem("_session_key")) {
        return;
      }

      // 2. Check persistent cache
      const cached = await getCachedKeys();
      if (cached) {
        sessionStorage.setItem("_session_key", cached.sessionKey);
        sessionStorage.setItem("_private_key", cached.privateKey);
        sessionStorage.setItem("_user_key", cached.userKey);
        return;
      }

      // 3. Derive from temp key (just logged in)
      const tempKey = sessionStorage.getItem("_session_key_temp");
      if (!tempKey) {
        window.location = "/users/reauthenticate";
        return;
      }

      await ensureReady();

      const el = this.el;
      const publicKey = el.dataset.publicKey;
      const encryptedPrivateKey = el.dataset.encryptedPrivateKey;
      const encryptedUserKey = el.dataset.encryptedUserKey;

      // Decrypt private key with session key
      const privateKey = decrypt(encryptedPrivateKey, tempKey);

      // Unseal user_key with keypair
      const userKey = unseal(encryptedUserKey, publicKey, privateKey);

      // Store in sessionStorage
      sessionStorage.setItem("_session_key", tempKey);
      sessionStorage.setItem("_private_key", privateKey);
      sessionStorage.setItem("_user_key", userKey);

      sessionStorage.removeItem("_session_key_temp");

      // Cache for browser restart
      cacheKeys(tempKey, privateKey, userKey);
    }
  }
</script>
```

## Step 4: Encrypting Resources

Here's how to encrypt a habit (or any resource) before it reaches the server.

### Colocated Hook for Creating a Resource

```heex
<%!-- lib/my_app_web/live/habit_live/index.html.heex --%>
<.form for={@form} id="new-habit-form" phx-hook=".HabitFormHook">
  <.input type="text" field={@form[:name]} />
  <.input type="textarea" field={@form[:encrypted_name]} name="habit[encrypted_name]" />
  <.input type="textarea" field={@form[:encrypted_description]} name="habit[encrypted_description]" />
  <button type="submit">Create Habit</button>
</.form>

<script :type={Phoenix.LiveView.ColocatedHook} name=".HabitFormHook">
  import { ensureReady, generateKey, seal, encrypt } from "../../js/crypto/nacl";

  export default {
    mounted() {
      this.el.addEventListener("submit", async (e) => {
        const userKey = sessionStorage.getItem("_user_key");
        if (!userKey) {
          e.preventDefault();
          window.location = "/users/reauthenticate";
          return;
        }

        e.preventDefault();
        await ensureReady();

        const name = this.el.querySelector('input[name="habit[name]"]').value;
        const description = this.el.querySelector('textarea[name="habit[description]"]').value;
        const publicKey = sessionStorage.getItem("_public_key");

        // Generate a per-habit context key
        const habitKey = generateKey();

        // Encrypt the fields
        const encryptedName = encrypt(name, habitKey);
        const encryptedDescription = encrypt(description, habitKey);

        // Seal the habit key to the user's public key
        const encryptedKey = seal(habitKey, publicKey);

        // Populate hidden fields
        this.el.querySelector('input[name="habit[encrypted_name]"]').value = encryptedName;
        this.el.querySelector('input[name="habit[encrypted_description]"]').value = encryptedDescription;
        this.el.querySelector('input[name="habit[encrypted_key]"]').value = encryptedKey;

        this.el.submit();
      });
    }
  }
</script>
```

### Server Handler

```elixir
defmodule MyAppWeb.HabitLive do
  use MyAppWeb, :live_view

  def handle_event("save", %{"habit" => habit_params}, socket) do
    attrs = %{
      encrypted_name: habit_params["encrypted_name"],
      encrypted_description: habit_params["encrypted_description"],
      user_id: socket.assigns.current_scope.user.id
    }

    case MyApp.Habits.create_habit(attrs) do
      {:ok, _habit} ->
        {:noreply, assign(socket, form: to_form(%{}))}

      {:error, changeset} ->
        {:noreply, assign(socket, form: to_form(changeset))}
    end
  end
end
```

### Ecto Schema for Encrypted Resources

```elixir
defmodule MyApp.Habits.Habit do
  use Ecto.Schema
  use Cloak.Ecto.Schema, encrypted: [:encrypted_name, :encrypted_description]

  schema "habits" do
    field :encrypted_name, :binary
    field :encrypted_description, :binary

    belongs_to :user, MyApp.Accounts.User
    timestamps()
  end
end

defmodule MyApp.Habits.UserHabit do
  use Ecto.Schema
  use Cloak.Ecto.Schema, encrypted: [:encrypted_key]

  schema "user_habits" do
    field :encrypted_key, :binary  # habit_key sealed for this user

    belongs_to :user, MyApp.Accounts.User
    belongs_to :habit, MyApp.Habits.Habit
    timestamps()
  end
end
```

## Step 5: Server-Side Key Distribution

When User A shares a resource with User B, the server needs to seal the context
key to User B's public key. User A may be offline, so the server does this using
the `metamorphic_crypto` NIF.

```elixir
defmodule MyApp.KeyDistribution do
  alias MyApp.Accounts

  def seal_key_for_user(context_key, user) do
    # The server can seal a context key to any user's public key
    # It never sees the plaintext context key — it only handles the sealed blob
    {:ok, sealed_key} = MetamorphicCrypto.BoxSeal.seal_raw(context_key, user.public_key)
    sealed_key
  end

  def distribute_key(habit, user_to_add, sealed_by_user_id) do
    # Fetch the user's public key
    user = Accounts.get_user!(user_to_add)

    # In a real app, you'd have the original context key available
    # from the user_habits record of an existing member
    existing = Repo.get_by(UserHabit, habit_id: habit.id, user_id: sealed_by_user_id)
    {:ok, context_key} = MetamorphicCrypto.BoxSeal.open_raw(existing.encrypted_key,
      existing.user.public_key, existing.user.private_key)

    # Seal it for the new user
    {:ok, sealed} = MetamorphicCrypto.BoxSeal.seal_raw(context_key, user.public_key)

    Repo.insert!(%UserHabit{
      user_id: user.id,
      habit_id: habit.id,
      encrypted_key: sealed
    })
  end
end
```

## Step 6: Displaying Encrypted Data

When sending encrypted data to the client, pass the encrypted blobs and keys
as data attributes on the LiveView elements:

```heex
<div
  :for={habit <- @habits}
  id={"habit-#{habit.id}"}
  phx-hook=".HabitCard"
  data-encrypted-name={habit.encrypted_name}
  data-encrypted-description={habit.encrypted_description}
  data-encrypted-key={habit.user_habit.encrypted_key}
>
  <p class="text-base-content">Encrypted — decrypting...</p>
</div>
```

### The Decryption Hook

```javascript
<script :type={Phoenix.LiveView.ColocatedHook} name=".HabitCard">
  import { ensureReady, decrypt, unseal } from "../../js/crypto/nacl";

  export default {
    async mounted() {
      await ensureReady();

      const el = this.el;
      const privateKey = sessionStorage.getItem("_private_key");
      const publicKey = sessionStorage.getItem("_public_key");

      if (!privateKey) {
        window.location = "/users/reauthenticate";
        return;
      }

      // Unseal the habit key
      const encryptedKey = el.dataset.encryptedKey;
      const habitKey = unseal(encryptedKey, publicKey, privateKey);

      // Decrypt the fields
      const name = decrypt(el.dataset.encryptedName, habitKey);
      const description = decrypt(el.dataset.encryptedDescription, habitKey);

      // Update the card
      el.querySelector('[data-decrypt-name]').textContent = name;
      el.querySelector('[data-decrypt-description]').textContent = description;
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
gets only encrypted ciphertext.

### Cloak is Defense-in-Depth, Not the Primary Protection

The primary encryption is client-side XSalsa20-Poly1305 / ML-KEM-768. The Cloak
layer protects against DB-level compromise but is not the user's E2E encryption.
If you rotate your Cloak key, user data is still protected by the E2E layer.

### Key Rotation is Not Built In

This library uses a single-key design per context. If you need key rotation
(multiple active keys with version-tagged ciphertext), use Cloak for the Ecto
layer. MetamorphicCrypto's server-side role is key distribution and generation,
not rotation.

## Reading

- [Metamorphic encryption architecture](https://github.com/moss-piglet/metamorphic/blob/main/docs/ENCRYPTION_ARCHITECTURE.md)
— the production reference implementation
- [What Post-Quantum Encryption Means for Your Data](https://dev.to/mosspiglet/what-post-quantum-encryption-means-for-your-data)
- [Cloak](https://hex.pm/packages/cloak) — Ecto encrypted types and key rotation
- [metamorphic-crypto](https://github.com/moss-piglet/metamorphic-crypto)
- [libsodium documentation](https://doc.libsodium.org/) — wire format reference
