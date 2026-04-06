const express = require("express");
const { handleGitHubWebhook } = require("../controllers/webhookController");

const router = express.Router();

router.post("/", handleGitHubWebhook);

module.exports = router;
