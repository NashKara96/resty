# Bounty Fix

**Reward:** $10.00
**Issue:** https://github.com/NashKara96/resty/issues/1
**Repo:** https://github.com/NashKara96/resty

---

## Issue

🎯 Fix Race Condition and Stale Nonce Count in Concurrent Digest Authentication

## 📝 Description
When using Resty's built-in Digest Authentication support with a shared `resty.Client` instance, concurrent requests to the same endpoint can fail with `401 Unauthorized`. 

This occurs because the Digest access authentication state—specifically the nonce count (`nc`) and the client nonce (`cnonce`)—is mutated concurrently across goroutines without proper synchronization. Under concurrent load, multiple goroutines read the same stale `nc` value, generate identical authentication headers, and send them to the server. Servers that strictly validate the monotonic increase of the nonce count for a given active nonce will reject these duplicate or out-of-order requests.

## 🎯 Acceptance Criteria
- [ ] **Thread-Safe State Mutation**: Access to and mutation of the Digest Authentication state (specifically the nonce count `nc` and client nonce `cnonce`) must be thread-safe.
- [ ] **Monotonic Nonce Count**: Under concurrent requests, the nonce count (`nc`) sent to the server must monotonically increase for any given active server `nonce`.
- [ ] **No Data Races**: Running tests with the Go race detector (`go test -race ./...`) must not report any data races in the digest authentication flow.
- [ ] **Backward Compatibility**: The fix must not break the existing public API of `resty.Client` or the way Digest Auth is configured by users.

## 🛠️ Technical Specifications & Context
In `NashKara96/resty` (a Go HTTP client library), Digest Authentication is typically handled during the request execution lifecycle (likely within `client.go`, `request.go`, or a dedicated helper file handling digest challenges).

### Proposed Implementation Details:
1. **Locate the Digest State**: Identify where the digest credentials, server `nonce`, and client `nc` counter are stored. This is likely in a struct representing the digest credentials or transport state associated with the client.
2. **Synchronize Access**: 
   - Introduce a `sync.Mutex` to protect the digest state struct, or utilize atomic operations (`sync/atomic`) to increment the nonce count (`nc`) safely.
   - Ensure that the generation of the `Authorization` header (which computes the MD5 response hash using `nc` and `cnonce`) is performed within a critical section or uses snapshot values of the state to prevent dirty reads.
3. **Handle Nonce Updates**: If the server returns a new `nonce` (e.g., via a `stale=true` directive in a `401` response), the local `nc` counter must be safely reset to `1` under the same synchronization lock.

## 🧪 Verification & Testing
To verify the fix, implement a concurrent integration test:

1. **Mock Digest Server**: Create a test HTTP server using `net/http/httptest` that implements Digest Authentication and strictly tracks the `nc` value for the active nonce. If it receives a request with an `nc` value less than or equal to the highest `nc` received so far for that nonce, it must return a `401 Unauthorized`.
2. **Concurrent Client Test**:
   ```go
   func TestDigestAuth_Concurrency(t *testing.T) {
       // 1. Set up the strict mock digest server
       // 2. Initialize a single resty.Client with Digest Auth credentials
       // 3. Launch 50 concurrent goroutines making GET requests to the server
       // 4. Assert that all 50 requests succeed with 200 OK and no 401 errors are returned
   }
   ```
3. **Race Detection**: Run the test suite using the race detector to ensure no data races exist:
   ```bash
   go test -race -v -run=TestDigestAuth_Concurrency
   ```

---

[![Opire Bounty](https://img.shields.io/badge/bounty-Opire-emerald?style=for-the-badge)](https://github.com/NashKara96/resty)
<br/>
<hr/>

<details><summary>This repo is using Opire - what does it mean? 👇</summary><br/>💵 Everyone can add rewards for this issue commenting <code>/reward 100</code> (replace <code>100</code> with the amount).<br/>🕵️‍♂️ If someone starts working on this issue to earn the rewards, they can comment <code>/try</code> to let everyone know!<br/>🙌 And when they open the PR, they can comment <code>/claim #1</code> either in the PR description or in a PR's comment.<br/><br/>🪙 Also, everyone can tip any user commenting <code>/tip 20 @NashKara96</code> (replace <code>20</code> with the amount, and <code>@NashKara96</code> with the user to tip).<br/><br/>📖 If you want to learn more, check out our <a href="https://docs.opire.dev">documentation</a>.</details>

---

## Process

### 1. Orient yourself first
Before touching any code:
- Read the README and any relevant docs
- Run: find . -type f | grep -v node_modules | grep -v .git | grep -v dist | head -60
- Grep for the key terms from the issue title to find the relevant files
- Read the files around the bug — understand what's currently happening

### 2. Find and read the tests
- Look for test files near the relevant code (*.test.ts, *.spec.js, __tests__, etc.)
- Read them — they tell you what behavior is expected
- Understand what a passing fix looks like before writing a line

### 3. Implement the fix
- Make the MINIMAL change that fixes the issue — nothing more
- Do not refactor, rename, reorganize, or clean up unrelated code
- Do not add dependencies unless the issue explicitly requires it
- Do not modify config files (package.json, tsconfig.json, etc.) unless that IS the fix
- One logical change, one commit

### 4. Verify
- Run the test suite: check package.json scripts for "test", "lint", "typecheck"
  Common commands: npm test, yarn test, pnpm test, pytest, go test ./..., cargo test
- If TypeScript is present: npx tsc --noEmit
- Fix any test failures your change caused — if a test was wrong before, update it

### 5. Commit and document
- git add -A
- git commit -m "fix: 🎯 Fix Race Condition and Stale Nonce Count in Concurrent Digest Authent"
- Write AGENT_SUMMARY.md with:
  - Root cause: what was wrong and why
  - Fix: what you changed and the reasoning
  - Verification: how to confirm it works
  - Concerns: anything a reviewer should know

---

## Stop conditions

If ANY of these are true, write "UNCERTAIN: [reason]" at the top of AGENT_SUMMARY.md, make NO code changes, and stop:
- The fix requires changing more than ~5 files
- You cannot determine what the correct behavior should be
- The issue requires a database migration, API key, or external service
- You find 3+ open PRs already attempting this fix (high competition)
- The repo is not in a language/framework you can reason about confidently

A clean UNCERTAIN is better than a bad PR.
