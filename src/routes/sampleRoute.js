// Sample route
const express = require('express');
const router = express.Router();
const { home } = require('../controllers/sampleController');

router.get('/', home);

module.exports = router;