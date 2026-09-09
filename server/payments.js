const Stripe = require('stripe');

const stripeSecretKey = process.env.STRIPE_SECRET_KEY;
const stripe = stripeSecretKey ? new Stripe(stripeSecretKey) : null;

function requireStripe() {
  if (!stripe) throw new Error('Stripe is not configured');
  return stripe;
}

async function createCheckoutSession({ purchaseId, book, readerEmail }) {
  const client = requireStripe();
  const appUrl = process.env.APP_URL;
  if (!appUrl) throw new Error('APP_URL is not configured');

  return client.checkout.sessions.create({
    mode: 'payment',
    customer_email: readerEmail,
    line_items: [{
      price_data: {
        currency: book.currency.toLowerCase(),
        product_data: { name: book.title, description: book.description.slice(0, 500) },
        unit_amount: book.price
      },
      quantity: 1
    }],
    metadata: { purchaseId, bookId: book.id },
    success_url: `${appUrl.replace(/\/$/, '')}/?checkout=success&session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${appUrl.replace(/\/$/, '')}/?checkout=cancelled`
  });
}

function constructWebhookEvent(payload, signature) {
  const client = requireStripe();
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) throw new Error('STRIPE_WEBHOOK_SECRET is not configured');
  return client.webhooks.constructEvent(payload, signature, secret);
}

module.exports = { createCheckoutSession, constructWebhookEvent };
