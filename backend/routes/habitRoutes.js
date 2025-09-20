const express = require('express');
const { createHabit, getUserHabits ,updateHabit, deleteHabit ,deleteAllHabits,trackProgress,getHabitById} = require('../controllers/habitController');
const auth = require('../middleware/auth');

const router = express.Router();

// Create habit (protected)
router.post('/', auth, createHabit);

// Get user habits (protected)
router.get('/', auth, getUserHabits);

// Update habit (protected)
router.put('/:id', auth, updateHabit);

// Delete habit (protected)
router.delete('/:id', auth, deleteHabit);

// Delete all habits (protected)
router.delete('/all', auth, deleteAllHabits);

//for the habbit progress
router.put('/:habitId/progress', auth, trackProgress);


// Get specific habit by ID (protected)
router.get('/:id', auth, getHabitById);



module.exports = router;
