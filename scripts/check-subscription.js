#!/usr/bin/env node
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

/**
 * Check Subscription Status Script
 * 
 * Usage: node scripts/check-subscription.js <email>
 */

async function checkSubscription(email) {
  if (!email) {
    console.error('❌ Email is required');
    console.log('Usage: node scripts/check-subscription.js <email>');
    process.exit(1);
  }

  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY
  );

  try {
    console.log(`\n🔍 Checking subscription for: ${email}`);

    // Get user by email
    const { data: userData, error: userError } = await supabase.auth.admin.listUsers();
    
    if (userError) {
      console.error('❌ Error fetching users:', userError.message);
      process.exit(1);
    }

    const user = userData?.users?.find(u => u.email === email);

    if (!user) {
      console.error(`❌ User with email ${email} not found`);
      process.exit(1);
    }

    console.log(`✅ Found user: ${user.email} (ID: ${user.id})`);

    // Get subscription
    const { data: subscription, error } = await supabase
      .from('user_subscriptions')
      .select('*')
      .eq('user_id', user.id)
      .maybeSingle();

    if (error) {
      console.error('❌ Error fetching subscription:', error.message);
      process.exit(1);
    }

    console.log('\n📊 Subscription Status:');
    
    if (!subscription) {
      console.log('   Plan: FREE (no subscription found)');
      console.log('   Status: N/A');
      console.log('\n💡 Use grant-premium.js to add a subscription');
    } else {
      console.log(`   Plan: ${subscription.plan.toUpperCase()}`);
      console.log(`   Status: ${subscription.status}`);
      console.log(`   Started: ${new Date(subscription.started_at).toLocaleString()}`);
      
      if (subscription.expires_at) {
        const expiresAt = new Date(subscription.expires_at);
        const now = new Date();
        const daysRemaining = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24));
        
        console.log(`   Expires: ${expiresAt.toLocaleString()}`);
        console.log(`   Days Remaining: ${daysRemaining > 0 ? daysRemaining : 'EXPIRED'}`);
        
        if (daysRemaining <= 0) {
          console.log('\n⚠️  Subscription has EXPIRED');
        } else if (daysRemaining <= 7) {
          console.log('\n⚠️  Subscription expires soon!');
        }
      } else {
        console.log('   Expires: Never (permanent)');
      }

      if (subscription.stripe_payment_intent) {
        console.log(`   Payment: ${subscription.stripe_payment_intent}`);
      }

      console.log('\n🎯 Available Features:');
      console.log(`   ✓ Link expiration: ${subscription.plan !== 'free' ? 'YES' : 'NO'}`);
      console.log(`   ✓ Link editing: ${subscription.plan !== 'free' ? 'YES' : 'NO'}`);
      console.log(`   ✓ Bulk shortening: ${subscription.plan !== 'free' ? 'YES' : 'NO'}`);
      console.log(`   ✓ Custom branding: ${subscription.plan === 'enterprise' ? 'YES' : 'NO'}`);
    }

  } catch (err) {
    console.error('❌ Unexpected error:', err.message);
    process.exit(1);
  }
}

const email = process.argv[2];
checkSubscription(email);
