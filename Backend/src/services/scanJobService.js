const ScanJob = require("../models/ScanJob");

const updateScanJobByQueueId = async (queueJobId, updates) => {
  if (!queueJobId) {
    return null;
  }

  return ScanJob.findOneAndUpdate({ queueJobId }, updates, {
    new: true,
  });
};

module.exports = {
  updateScanJobByQueueId,
};
