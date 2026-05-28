/**
 * verify-prod.js  —  READ-ONLY production checks for Q1 / Q4 / Q6.
 *
 * Runs three SELECT-only checks and prints PASS / WARN / FAIL in plain English.
 * It does NOT write, alter, or delete anything. Safe to run any time.
 *
 * EASIEST WAY TO RUN (no setup):
 *   1. Render Dashboard → your web service (totalfooty-api) → "Shell" tab
 *   2. Upload this file, or paste it: cat > verify-prod.js  (paste, then Ctrl-D)
 *   3. Run:  node verify-prod.js
 *   (DATABASE_URL and the 'pg' module already exist in that environment.)
 *
 * ALTERNATIVE (your own machine):
 *   DATABASE_URL="<External DB URL from Render>" node verify-prod.js
 */

const { Pool } = require('pg');

const TF_COVENTRY_TENANT_ID = '11111111-1111-1111-1111-111111111111';
const EXPECTED_FAQ_COUNT = 43;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Render Postgres requires SSL
});

function line() { console.log('─'.repeat(60)); }

async function q1_faqs() {
  console.log('\nQ1 — FAQs seeded? (Bug 6 root cause)');
  line();
  try {
    const r = await pool.query('SELECT COUNT(*)::int AS n, bool_and(active) AS all_active FROM faq_entries');
    const n = r.rows[0].n;
    const allActive = r.rows[0].all_active;
    console.log(`   faq_entries rows: ${n}   |   all active: ${allActive}`);
    if (n === 0) {
      console.log('   ❌ FAIL — table is EMPTY. Seed never ran. This IS Bug 6.');
      console.log('      Fix: trigger a fresh boot (redeploy) so fix356BootstrapFaq seeds,');
      console.log('      or check boot logs for the "📚 FIX-356: seeding…" line / errors.');
    } else if (n < EXPECTED_FAQ_COUNT) {
      console.log(`   ⚠ WARN — only ${n}/${EXPECTED_FAQ_COUNT} seeded. Partial seed.`);
    } else if (allActive === false) {
      console.log(`   ⚠ WARN — ${n} rows but some are inactive. Public endpoint only serves active=true.`);
    } else {
      console.log(`   ✅ PASS — ${n} FAQs, all active. If users still see none → FRONTEND / cache issue,`);
      console.log('      not the DB. Check /api/public/faqs response + Cloudflare cache on faq.html.');
    }
  } catch (e) {
    if (e.code === '42P01') console.log('   ❌ FAIL — table faq_entries DOES NOT EXIST. Bootstrap never created it.');
    else console.log('   ❌ ERROR —', e.message);
  }
}

async function q4_multiregion() {
  console.log('\nQ4 — Multi-region migration (players.region_codes)');
  line();
  try {
    const col = await pool.query(
      `SELECT data_type FROM information_schema.columns
        WHERE table_name='players' AND column_name='region_codes'`
    );
    if (col.rows.length === 0) {
      console.log('   ❌ FAIL — players.region_codes column MISSING. Migration not applied.');
      return;
    }
    console.log(`   Column exists. type: ${col.rows[0].data_type}`);

    const counts = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM players WHERE region_code IS NOT NULL AND region_code <> '')::int AS legacy,
        (SELECT COUNT(*) FROM players WHERE region_codes IS NOT NULL AND cardinality(region_codes) > 0)::int AS arr,
        (SELECT COUNT(*) FROM players)::int AS total
    `);
    const { legacy, arr, total } = counts.rows[0];
    console.log(`   players total: ${total}  |  legacy region_code set: ${legacy}  |  region_codes[] set: ${arr}`);
    if (legacy === arr) {
      console.log('   ✅ PASS — legacy and array counts MATCH. Backfill complete.');
    } else {
      console.log(`   ⚠ WARN — counts differ by ${Math.abs(legacy - arr)}. Backfill incomplete or new signups not populating region_codes[].`);
    }

    const sample = await pool.query(`
      SELECT id, region_code, region_codes, created_at
        FROM players
       WHERE created_at > NOW() - INTERVAL '24 hours'
       ORDER BY created_at DESC LIMIT 5
    `);
    if (sample.rows.length === 0) {
      console.log('   (no signups in last 24h to sample — fine)');
    } else {
      console.log('   Recent signups (check region_codes[] is populated, not just region_code):');
      sample.rows.forEach(r =>
        console.log(`      ${String(r.id).slice(0,8)}…  region_code=${r.region_code}  region_codes=${JSON.stringify(r.region_codes)}`)
      );
    }
  } catch (e) {
    console.log('   ❌ ERROR —', e.message);
  }
}

async function q6_coventry() {
  console.log('\nQ6 — Coventry magic tenant exists? (payout skip logic)');
  line();
  try {
    const r = await pool.query(
      'SELECT id, name, status FROM tenants WHERE id = $1',
      [TF_COVENTRY_TENANT_ID]
    );
    if (r.rows.length === 0) {
      console.log(`   ❌ FAIL — tenant ${TF_COVENTRY_TENANT_ID} DOES NOT EXIST.`);
      console.log('      The payout-skip at server.js:21791 keys off this ID. If absent,');
      console.log('      Coventry games may generate payouts due to a tenant that isn\'t there.');
    } else {
      const t = r.rows[0];
      console.log(`   ✅ PASS — found: name="${t.name}"  status="${t.status}"`);
    }
  } catch (e) {
    if (e.code === '42P01') console.log('   ❌ FAIL — tenants table does not exist (multi-tenant bootstrap never ran).');
    else console.log('   ❌ ERROR —', e.message);
  }
}

(async () => {
  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL not set in this environment. Run inside Render shell, or pass it inline.');
    process.exit(1);
  }
  console.log('TotalFooty prod verification — READ ONLY (no writes)');
  await q1_faqs();
  await q4_multiregion();
  await q6_coventry();
  console.log('\nDone. Nothing was modified.');
  await pool.end();
})().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
