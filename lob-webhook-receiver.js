/**
 * Lob -> HubSpot webhook receiver (unified: mail status + QR scans)
 * ------------------------------------------------------------------
 * One endpoint that Lob calls on every letter.* event. It maps Lob's
 * event to the HubSpot contact and updates:
 *   - lob_last_status        (enumeration)  <- status events
 *   - lob_last_status_date   (date, YYYY-MM-DD)
 *   - lob_tracking_active    ('false')       <- only on terminal events
 *   - lob_qr_scans           (incremented)   <- letter.viewed events
 *
 * The contact is found from metadata.hubspot_id that the letter-creation
 * step stamped on the mail piece; if that is missing it falls back to a
 * CRM search on lob_letter_id.
 *
 * Deploy anywhere that runs Node (Render, Cloud Run, Fly, Lambda, a small
 * VM, etc.). Set two environment variables:
 *   HUBSPOT_TOKEN        - a HubSpot private-app token with crm.objects.contacts read+write
 *   LOB_WEBHOOK_SECRET   - the signing secret shown when you create the webhook in Lob
 *                          (optional but strongly recommended; if unset, signature
 *                           verification is skipped)
 *
 * Then in the Lob dashboard add a webhook pointing at  https://YOUR-HOST/lob-webhook
 * subscribed to the letter.* events listed in STATUS_MAP plus letter.viewed.
 */

const express = require('express');
const crypto = require('crypto');
const axios = require('axios');

const HUBSPOT_TOKEN = process.env.HUBSPOT_TOKEN;
const LOB_WEBHOOK_SECRET = process.env.LOB_WEBHOOK_SECRET || '';

// Lob event id  ->  lob_last_status enumeration value (HubSpot).
// Note the hyphen: Lob sends "letter.re_routed" but the HubSpot option is "re-routed".
const STATUS_MAP = {
  'letter.created': 'created',
  'letter.rendered_pdf': 'rendered',
  'letter.mailed': 'mailed',
  'letter.in_transit': 'in_transit',
  'letter.in_local_area': 'in_local_area',
  'letter.processed_for_delivery': 'processed_for_delivery',
  'letter.re-routed': 're-routed',
  'letter.re_routed': 're-routed', // accept both spellings, just in case
  'letter.returned_to_sender': 'returned_to_sender',
  'letter.delivered': 'delivered',
  'letter.failed': 'failed',
  // letter.international_exit is intentionally not mapped (domestic mail only).
};

// Once a letter hits one of these, stop tracking it.
const TERMINAL = new Set(['delivered', 'returned_to_sender', 'failed']);

const hsHeaders = () => ({ Authorization: `Bearer ${HUBSPOT_TOKEN}`, 'Content-Type': 'application/json' });

// ---- HubSpot helpers -------------------------------------------------------

// Resolve the HubSpot contact id: prefer the stamped metadata, else search by letter id.
async function resolveContactId(letter) {
  const stamped = letter && letter.metadata && letter.metadata.hubspot_id;
  if (stamped) return String(stamped);

  const letterId = letter && letter.id;
  if (!letterId) return null;
  const res = await axios.post(
    'https://api.hubapi.com/crm/v3/objects/contacts/search',
    {
      filterGroups: [{ filters: [{ propertyName: 'lob_letter_id', operator: 'EQ', value: letterId }] }],
      properties: ['lob_qr_scans'],
      limit: 1,
    },
    { headers: hsHeaders() }
  );
  const hit = res.data && res.data.results && res.data.results[0];
  return hit ? hit.id : null;
}

async function patchContact(contactId, properties) {
  await axios.patch(
    `https://api.hubapi.com/crm/v3/objects/contacts/${contactId}`,
    { properties },
    { headers: hsHeaders() }
  );
}

// letter.viewed -> read current scan count, add one, write it back.
async function incrementQrScans(contactId) {
  const res = await axios.get(
    `https://api.hubapi.com/crm/v3/objects/contacts/${contactId}?properties=lob_qr_scans`,
    { headers: hsHeaders() }
  );
  const current = parseInt((res.data.properties || {}).lob_qr_scans, 10);
  const next = (Number.isFinite(current) ? current : 0) + 1;
  await patchContact(contactId, { lob_qr_scans: String(next) });
  return next;
}

// ---- Lob signature verification -------------------------------------------
// Lob signs with HMAC-SHA256 over `${timestamp}.${rawBody}`. Headers:
//   lob-signature, lob-signature-timestamp
function verifyLobSignature(req) {
  if (!LOB_WEBHOOK_SECRET) return true; // verification disabled
  const sig = req.get('lob-signature');
  const ts = req.get('lob-signature-timestamp');
  if (!sig || !ts) return false;
  const expected = crypto
    .createHmac('sha256', LOB_WEBHOOK_SECRET)
    .update(`${ts}.${req.rawBody}`, 'utf8')
    .digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch (_) {
    return false;
  }
}

// ---- HTTP app --------------------------------------------------------------

const app = express();
// Capture the raw body (needed for signature verification) while still parsing JSON.
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString('utf8');
    },
  })
);

app.post('/lob-webhook', async (req, res) => {
  if (!verifyLobSignature(req)) {
    return res.status(401).send('bad signature');
  }

  const event = req.body || {};
  const eventId = (event.event_type && event.event_type.id) || event.type || '';
  const letter = event.body || {};
  // Time the event occurred -> YYYY-MM-DD for the date property.
  const when = event.date_created || (letter && letter.date_created);
  const statusDate = when ? new Date(when).toISOString().split('T')[0] : '';

  // Always ack quickly so Lob does not retry; do the work, then respond.
  try {
    const contactId = await resolveContactId(letter);
    if (!contactId) {
      console.warn(`No HubSpot contact for event ${eventId} (letter ${letter.id || '?'})`);
      return res.status(200).send('no-contact'); // 200 so Lob does not keep retrying
    }

    if (eventId === 'letter.viewed') {
      const total = await incrementQrScans(contactId);
      console.log(`QR scan -> contact ${contactId} now ${total}`);
      return res.status(200).send('qr-ok');
    }

    const statusValue = STATUS_MAP[eventId];
    if (!statusValue) {
      // An event we don't track (e.g. international_exit, rendered_thumbnails).
      return res.status(200).send('ignored');
    }

    const properties = { lob_last_status: statusValue, lob_last_status_date: statusDate };
    if (TERMINAL.has(statusValue)) properties.lob_tracking_active = 'false';
    await patchContact(contactId, properties);
    console.log(`Status ${statusValue} -> contact ${contactId}`);
    return res.status(200).send('status-ok');
  } catch (err) {
    const detail = err.response ? JSON.stringify(err.response.data) : err.message;
    console.error(`Handler error for ${eventId}: ${detail}`);
    return res.status(500).send('error');
  }
});

app.get('/health', (_req, res) => res.status(200).send('ok'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Lob webhook receiver listening on :${PORT}`));

module.exports = app;
