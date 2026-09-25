# DataCooker TikTok BS Sync on Cloudflare

Cloudflare Worker nay dung Browser Run va Playwright de xu ly cac job trong
`public.tiktok_bs_sync_jobs`.

Worker van giu nguyen cac route Facebook OAuth hien tai:

- `/auth/facebook/launch`
- `/auth/facebook/callback`
- `/auth/facebook/session-check`

Custom domain `https://datacooker.io.vn` phai tiep tuc tro den Worker nay.

## Trien khai

Yeu cau Node.js 20 tro len va mot tai khoan Cloudflare co Browser Run.

```bash
npm install
npx wrangler login
npx wrangler secret put SUPABASE_URL
npx wrangler secret put SUPABASE_SERVICE_ROLE_KEY
npx wrangler secret put TIKTOK_BS_ENCRYPTION_KEY
npx wrangler secret put WORKER_SECRET
npm run deploy
```

`TIKTOK_BS_ENCRYPTION_KEY` phai giong het secret dang dung trong Supabase Edge
Function. Khong dat service-role key hoac encryption key trong `wrangler.jsonc`.

Cron chay moi phut va claim toi da mot job trong moi lan chay. Co the chay thu
thu cong sau khi deploy:

```bash
curl -X POST "https://datacooker-tiktok-bs-sync.YOUR_SUBDOMAIN.workers.dev/run" \
  -H "Authorization: Bearer YOUR_WORKER_SECRET"
```

Kiem tra `/health` khong can khoa. Endpoint `/run` bat buoc co Bearer secret.

## Thu tu cap nhat he thong

1. Chay `TikTok BS Worker Migration.sql` trong Supabase SQL Editor.
2. Deploy ban Edge Function moi.
3. Dat bon Cloudflare secrets va deploy Worker nay.
4. Nhap BC ID, ten nguon va TikTok Cookie/Session tren Sidebar.
5. Kiem tra `tiktok_bs_sync_jobs`, `tiktok_bs_business_suites`,
   `tiktok_bs_accounts`, `tiktok_bs_ad_accounts` va `tiktok_bs_metrics`.

Worker khong ghi Cookie vao log, response hoac bang snapshot. Session chi duoc
giai ma trong bo nho trong luc xu ly job.


