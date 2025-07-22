import mongoose from 'mongoose';

const cursorEventSchema = new mongoose.Schema({
  sessionId: { type: String, required: true, index: true },
  time_ms: [{ type: Number, required: true }],
  x: [{ type: Number, required: true }],
  y: [{ type: Number, required: true }],
}, { timestamps: true });

export default mongoose.model('CursorEvent', cursorEventSchema);


