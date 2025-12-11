#!/usr/bin/env node
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

/**
 * Revoke Premium Access Script
 * 
 * Usage: node scripts/revoke-premium.js <email>
 */

async function revokePremium(email) {
  if (!email) {
    console.error('❌ Email is required');
    console.log('Usage: node scripts/revoke-premium.js <email>');
    process.exit(1);
  }

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
      process.exit(1);
    }

    console.log(`✅ Found user: ${user.email} (ID: ${user.id})`);

    // Update subscription to free/cancelled
    const { error } = await supabase
      .from('user_subscriptions')
      .update({
        plan: 'free',
        status: 'cancelled',
        updated_at: new Date().toISOString()
      })
      .eq('user_id', user.id);

    if (error) {
      console.error('❌ Error revoking premium:', error.message);
      process.exit(1);
    }

    console.log('\n✅ Premium access revoked successfully!');
    console.log(`   User ${email} is now on the FREE plan`);

  } catch (err) {
    console.error('❌ Unexpected error:', err.message);
    process.exit(1);
  }
}

const email = process.argv[2];
revokePremium(email);
