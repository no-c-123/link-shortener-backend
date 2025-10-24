require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 5001;

// ✅ CORS setup
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
}));
app.options('*', cors());

app.use(express.json());

// ✅ Supabase Setup
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// ✅ Save to Database
app.post('/shorten', async (req, res) => {
    const { originalUrl, customCode } = req.body;
    const code = customCode || Math.random().toString(36).substring(2, 7);

    if (!originalUrl) {
        return res.status(400).json({ error: 'Missing URL' });
    }

    try {
        const { error } = await supabase
            .from('links')
            .insert([{ code, original: originalUrl }]);

        if (error) {
            return res.status(500).json({ error: 'Database error', details: error.message });
        }

        res.json({
            shortUrl: `https://link-shortener-backend-production.up.railway.app/${code}`,
        });
    } catch (err) {
        res.status(500).json({ error: 'Unexpected server error', details: err.message });
    }
});

// ✅ Retrieve from Database
app.get('/:code', async (req, res) => {
    const { code } = req.params;

    const { data, error } = await supabase
        .from('links')
        .select('original, click_count')
        .eq('code', code)
        .single();

    if (error || !data) return res.status(404).send('Link not found');

    await supabase
        .from('links')
        .update({ click_count: (data.click_count ?? 0) + 1})
        .eq('code', code);


    res.redirect(data.original);
});

app.get('/info/:code', async (req, res) => {
    const { code } = req.params;

    const { data, error } = await supabase
        .from('links')
        .select('*')
        .eq('code', code)
        .single();

    if (error || !data) {
        return res.status(404).json({ error: 'Link not found' });
    }

    res.json(data);
});

// ✅ Start Server
app.listen(PORT, () => {
    console.log(`Backend running on http://localhost:${PORT}`);
});