const Habit = require('../models/Habit');
const User = require('../models/User');
const logger = require('../utils/logger');

const VALID_FREQUENCIES = ['daily', 'weekly', 'custom'];

const createHabit = async (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    // Optional: confirm user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const {
      title,
      description,
      frequency = 'daily',
      daysOfWeek,
      reminderTime,
      color,
      icon,
      startDate,
      endDate
    } = req.body;

    if (!title || typeof title !== 'string' || title.trim().length < 1) {
      return res.status(400).json({ success: false, message: 'Title is required' });
    }

    if (!VALID_FREQUENCIES.includes(frequency)) {
      return res.status(400).json({ success: false, message: 'Invalid frequency' });
    }

    if (frequency === 'custom' && (!Array.isArray(daysOfWeek) || daysOfWeek.length === 0)) {
      return res.status(400).json({ success: false, message: 'daysOfWeek is required for custom frequency' });
    }

    if (Array.isArray(daysOfWeek)) {
      const invalidDay = daysOfWeek.find(d => typeof d !== 'number' || d < 0 || d > 6);
      if (invalidDay !== undefined) {
        return res.status(400).json({ success: false, message: 'daysOfWeek must be numbers between 0 and 6' });
      }
    }

    if (startDate && endDate) {
      const s = new Date(startDate);
      const e = new Date(endDate);
      if (isNaN(s) || isNaN(e) || s > e) {
        return res.status(400).json({ success: false, message: 'Invalid startDate/endDate range' });
      }
    }

    // Optional: avoid exact duplicate titles for same user
    const existing = await Habit.findOne({ user: userId, title: title.trim() });
    if (existing) {
      // you can change behavior: allow duplicates or return conflict
      return res.status(409).json({ success: false, message: 'You already have a habit with this title' });
    }

    const habit = new Habit({
      user: userId,
      title: title.trim(),
      description,
      frequency,
      daysOfWeek: Array.isArray(daysOfWeek) ? daysOfWeek : undefined,
      reminderTime: reminderTime || null,
      color: color || undefined,
      icon: icon || undefined,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined
    });

    await habit.save();

    logger.info('Habit created', { userId, habitId: habit._id });

    return res.status(201).json({ success: true, data: habit });
  } catch (error) {
    logger.error('Create habit failed', { error: error.message, stack: error.stack, userId: req.user?.id });
    return res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
  }
};

const getUserHabits = async (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    // Query params: page, limit, archived (archived=true|false)
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const limit = Math.max(parseInt(req.query.limit || '100', 10), 1);
    const archivedQuery = req.query.archived;

    const query = { user: userId };
    if (typeof archivedQuery !== 'undefined') {
      // allow archived=true or archived=false
      query.archived = archivedQuery === 'true';
    }

    const skip = (page - 1) * limit;

    const [habits, total] = await Promise.all([
      Habit.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit),
      Habit.countDocuments(query)
    ]);

    return res.status(200).json({
      success: true,
      data: habits,
      meta: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Get user habits failed', {
      error: error.message,
      stack: error.stack,
      userId: req.user?.id
    });
    return res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
  }
};

const updateHabit = async (req, res) => {
  try {
    const userId = req.user?.id;
    const habitId = req.params.id;
    const updates = req.body;

    if (!userId) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const habit = await Habit.findOne({ _id: habitId, user: userId });
    if (!habit) {
      return res.status(404).json({ success: false, message: 'Habit not found' });
    }

    // Update fields if present
    const allowedFields = ['title', 'description', 'frequency', 'daysOfWeek', 'reminderTime', 'color', 'icon', 'startDate', 'endDate', 'archived'];
    allowedFields.forEach(field => {
      if (updates[field] !== undefined) {
        habit[field] = updates[field];
      }
    });

    await habit.save();

    return res.status(200).json({ success: true, data: habit });
  } catch (error) {
    logger.error('Update habit failed', { error: error.message, stack: error.stack, userId: req.user?.id });
    return res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
  }
};

const deleteHabit = async (req, res) => {
  try {
    const userId = req.user?.id;
    const habitId = req.params.id;

    if (!userId) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const habit = await Habit.findOne({ _id: habitId, user: userId });
    if (!habit) {
      return res.status(404).json({ success: false, message: 'Habit not found' });
    }

    await habit.deleteOne();

    logger.info('Habit deleted', { userId, habitId });

    return res.status(200).json({ success: true, message: 'Habit deleted successfully' });
  } catch (error) {
    logger.error('Delete habit failed', { error: error.message, stack: error.stack, userId: req.user?.id });
    return res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
  }
};

const deleteAllHabits = async (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const result = await Habit.deleteMany({ user: userId });

    return res.status(200).json({
      success: true,
      message: `Deleted ${result.deletedCount} habit(s) successfully`
    });
  } catch (error) {
    logger.error('Delete all habits failed', {
      error: error.message,
      stack: error.stack,
      userId: req.user?.id
    });
    return res.status(500).json({ success: false, message: 'Something went wrong. Please try again later.' });
  }
};

const trackProgress = async (req, res) => {
  try {
    const { habitId } = req.params;
    const { date, done, note } = req.body;

    const habit = await Habit.findById(habitId);
    if (!habit) {
      return res.status(404).json({ success: false, message: 'Habit not found' });
    }

    const progressDate = new Date(date).toISOString().split('T')[0];

    // Check if already exists for that day
    const existingProgress = habit.progress.find(p => 
      new Date(p.date).toISOString().split('T')[0] === progressDate
    );

    if (existingProgress) {
      existingProgress.done = done;
      existingProgress.note = note || '';
    } else {
      habit.progress.push({ date: new Date(date), done, note: note || '' });
    }

    await habit.save();

    return res.status(200).json({ success: true, data: habit.progress });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Something went wrong' });
  }
};







module.exports = {
  createHabit,
  getUserHabits,
  updateHabit,
  deleteHabit,
  deleteAllHabits,
  trackProgress,
};
