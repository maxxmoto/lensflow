const drive = require('./drive');
const fs = require('fs');
const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'lensflow.db'));
const queue = [];
let working = false;

function add(job) {
  queue.push(job);
  processQueue();
}

async function processQueue() {
  if (working) return;
  working = true;
  console.log('Upload queue: processing', queue.length, 'jobs');

  while (queue.length > 0) {
    const job = queue.shift();
    try {
      await executeJob(job);
    } catch (e) {
      console.error('Upload queue job failed:', e.message);
    }
  }

  working = false;
}

async function executeJob(job) {
  const { filePath, fileName, albumId, albumTitle, photoId } = job;

  const result = await drive.uploadPhoto(filePath, fileName, albumId, albumTitle);
  console.log('Drive upload OK:', result.driveFileId, '-', fileName);

  // Save Drive file ID to database
  db.prepare('UPDATE photos SET drive_file_id = ? WHERE id = ?').run(result.driveFileId, photoId);

  // Remove local file after successful Drive upload (экономия 5GB диска)
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
    console.log('Local file removed:', filePath);
  }
}

function getQueueLength() { return queue.length; }
function isWorking() { return working; }

module.exports = { add, getQueueLength, isWorking };
