# admitone

The service is a Flask message board. Normal users can post messages via `/post`.

There is an admin-only endpoint `/admin_post` that reads an arbitrary file from the filesystem and posts its contents as an `admin` message. The flag is stored at `/flag`.

## Bug

The `/admin_post` route determines “admin” using a **cookie**:

- If `username == "admin"` then `status = "admin"`
- Otherwise it trusts the `status` cookie (`status = request.cookies.get("status")`)

So a normal user can set `status=admin` and satisfy the privilege check.

There is a second check on the `User-Agent`: it must be `MotorolaStarTAC/1.0`.

## Exploit

1. Register/login as any normal user (e.g. `bob`)
2. Send a request to `/admin_post` with:
   - Cookie `status=admin`
   - Header `User-Agent: MotorolaStarTAC/1.0`
   - Form field `filename=/flag`
3. Fetch `/` (still with `status=admin`) to see the admin-posted flag.

Run:

```bash
./exploit http://HOST:5544
```

