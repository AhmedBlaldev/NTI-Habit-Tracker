const mongoose = require('mongoose');

const progressSchema = new mongoose.Schema({
  date: { type: Date, required: true },
  done: { type: Boolean, default: false },
  note: { type: String, default: '' }
}, { _id: false });

const habitSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: [true, 'Title is required'], trim: true },
  description: { type: String, default: '' },
  frequency: {
    type: String,
    enum: ['daily', 'weekly', 'custom'],
    default: 'daily'
  },
  // for weekly/custom: array of days (0 = Sunday .. 6 = Saturday)
  daysOfWeek: { type: [Number], default: undefined },

  // reminder time as "HH:mm" string (optional)
  reminderTime: { type: String, default: null },

  color: { type: String, default: '#4caf50' },
  icon: { type: String, default: null },

  startDate: { type: Date, default: Date.now },
  endDate: { type: Date, default: null },

  // tracking progress entries
  progress: { type: [progressSchema], default: [] },

  archived: { type: Boolean, default: false }
}, {
  timestamps: true
});

habitSchema.index({ user: 1, title: 1 });

module.exports = mongoose.model('Habit', habitSchema);
