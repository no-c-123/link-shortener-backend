require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 5001; // Fixed port

// ✅ CORS setup
app.use(cors({
    origin: 'http://localhost:4321',
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
    const { originalUrl } = req.body;

    console.log('Request body:', req.body); // ✅ Check what the frontend is sending

    if (!originalUrl) {
        console.error('Missing URL in request');
        return res.status(400).json({ error: 'Missing URL' });
    }

    const code = Math.random().toString(36).substring(2, 7);

    try {
        const { error } = await supabase.from('links').insert([{ code, original: originalUrl }]);

        if (error) {
            console.error('Supabase insert error:', error); // ✅ Log the database error
            return res.status(500).json({ error: 'Database error', details: error.message });
        }

        res.json({ shortUrl: `http://localhost:${PORT}/${code}` });
    } catch (err) {
        console.error('Unexpected backend error:', err); // ✅ Catch any other errors
        res.status(500).json({ error: 'Unexpected server error', details: err.message });
    }
});

// ✅ Retrieve from Database
app.get('/:code', async (req, res) => {
    const { code } = req.params;

    const { data, error } = await supabase.from('links').select('original').eq('code', code).single();

    if (error || !data) return res.status(404).send('Link not found');

    res.redirect(data.original);
});

// ✅ Start Server
app.listen(PORT, () => {
    console.log(`Backend running on http://localhost:${PORT}`);
});