#!/usr/bin/env node
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

/**
 * Grant Premium Access Script
 * 
 * Usage: node scripts/grant-premium.js <email> <plan> <days>
 * 
 * Examples:
 *   node scripts/grant-premium.js admin@example.com pro 30
 *   node scripts/grant-premium.js test@example.com enterprise 365
 *   node scripts/grant-premium.js user@example.com pro 999999  (permanent)
 */

async function grantPremium(email, plan = 'pro', days = 30) {
  // Validate inputs
  if (!email) {
    console.error('❌ Email is required');
    console.log('Usage: node scripts/grant-premium.js <email> <plan> <days>');
    process.exit(1);
  }

  const validPlans = ['free', 'pro', 'enterprise'];
  if (!validPlans.includes(plan.toLowerCase())) {
    console.error(`❌ Invalid plan. Must be one of: ${validPlans.join(', ')}`);
    process.exit(1);
  }

  const daysNum = parseInt(days);
  if (isNaN(daysNum) || daysNum < 1) {
    console.error('❌ Days must be a positive number');
    process.exit(1);
  }

  // Initialize Supabase
  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY
  );

  try {
    console.log(`\n🔍 Looking for user with email: ${email}`);

    // Get user by email
    const { data: userData, error: userError } = await supabase.auth.admin.listUsers();
    
    if (userError) {
      console.error('❌ Error fetching users:', userError.message);
      process.exit(1);
    }

    const user = userData?.users?.find(u => u.email === email);

    if (!user) {
      console.error(`❌ User with email ${email} not found`);
      console.log('\n💡 Make sure the user has registered first!');
      process.exit(1);
    }

    console.log(`✅ Found user: ${user.email} (ID: ${user.id})`);

    // Calculate expiration
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + daysNum);

    console.log(`\n📦 Granting ${plan.toUpperCase()} plan for ${daysNum} days...`);
    console.log(`   Expires: ${expiresAt.toISOString()}`);

    // Upsert subscription
    const { data, error } = await supabase
      .from('user_subscriptions')
      .upsert({
        user_id: user.id,
        plan: plan.toLowerCase(),
        status: 'active',
        stripe_payment_intent: 'manual_grant',
        expires_at: expiresAt.toISOString(),
        started_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }, {
        onConflict: 'user_id'
      })
      .select();

    if (error) {
      console.error('❌ Error granting premium:', error.message);
      process.exit(1);
    }

    console.log('\n✅ Premium access granted successfully!');
    console.log('\n📊 Subscription Details:');
    console.log(`   User: ${email}`);
    console.log(`   Plan: ${plan.toUpperCase()}`);
    console.log(`   Status: active`);
    console.log(`   Expires: ${expiresAt.toLocaleDateString()} at ${expiresAt.toLocaleTimeString()}`);
    console.log(`   Days until expiration: ${daysNum}`);
    
    console.log('\n🎉 You can now test premium features with this account!');
    console.log('\nPremium Features Available:');
    console.log('   ✓ Link expiration');
    console.log('   ✓ Link editing (PATCH /links/:id)');
    console.log('   ✓ Bulk URL shortening (POST /shorten/bulk)');
    if (plan.toLowerCase() === 'enterprise') {
      console.log('   ✓ Custom branding (Enterprise only)');
    }

  } catch (err) {
    console.error('❌ Unexpected error:', err.message);
    process.exit(1);
  }
}

// Parse command line arguments
const args = process.argv.slice(2);
const email = args[0];
const plan = args[1] || 'pro';
const days = args[2] || '30';

grantPremium(email, plan, days);
