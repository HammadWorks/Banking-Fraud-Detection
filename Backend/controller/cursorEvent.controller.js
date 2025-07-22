import CursorEvent from '../models/cursorTrack.model.js';

const CursorEventHandler = async (req, res) => {
    try {
        const { sessionId, events } = req.body;

        // Validation
        if (!sessionId || !Array.isArray(events) || events.length === 0) {
            return res.status(400).json({ error: 'Missing sessionId or events array' });
        }

        // Limit to 100 session documents
        const count = await CursorEvent.countDocuments();
        if (count >= 100) {
            // Delete the oldest document (FIFO)
            const oldest = await CursorEvent.findOne().sort({ createdAt: 1 });
            if (oldest) {
                await CursorEvent.deleteOne({ _id: oldest._id });
            }
        }

        // Transform events into arrays
        const time_ms = events.map(ev => ev.time_ms);
        const x = events.map(ev => ev.x);
        const y = events.map(ev => ev.y);

        // Save as one document per session
        await CursorEvent.create({ sessionId, time_ms, x, y });

        res.status(201).json({ message: 'Events saved', count: events.length });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

export default CursorEventHandler;