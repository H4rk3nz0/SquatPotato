# SquatPotato
A SeImpersonate potato primitive that exploits squatting the IAiddService endpoint.

---

**Squattable endpoint.** `AiddService` is the `ncalrpc` server endpoint of **`InventorySvc`** ("Inventory and Compatibility Appraisal service"). The endpoint is registered by `aidd.dll` inside that service. `InventorySvc` idle-stops, so `\RPC Control\AiddService` is frequently absent. A standard user can create it - `SquatPotato` polls until the window opens, then holds it.

**The SYSTEM client.** `PcaSvc` (Program Compatibility Assistant Service, `LocalSystem`) contains an `AiddService` **client** (`pcasvc.dll!AiddRpcClient_Initialize`) and binds `ncalrpc:[AiddService]` with **no `RpcBindingSetAuthInfo`** it never authenticates the server). Its `AiddRpcClient_AsyncWorkerThread` periodically flushes queued **process-launch telemetry** to `AiddService` (fired by `LaunchedProcessDllDumper_ProcessStart`, enabled at service init).

**The summon happens on its own.** With the endpoint squatted, `PcaSvc` (SYSTEM) connects to our server **with no attacker action**, a normal background process launches keep its telemetry queue full and it flushes periodically. Observed connecting entirely passively within minutes.

**We register the interface and observe SYSTEM.** Our server registers `IAiddService` (`a7e3b8c1-4d2f-4e9a-b5c6-8f7d9e0a1b2c v1.0`) with **both** the classic NDR **and NDR64 (`71710533-BEBA-4937-8319-B5DBEF9CCC36`)** transfer syntaxes (PcaSvc's stub binds NDR64; registering classic-only silently fails the bind). Our RPC security callback fires and `RpcImpersonateClient` **succeeds**, reporting the caller as **`NT AUTHORITY\SYSTEM` / `S-1-5-18`**.
