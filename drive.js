const { google } = require('googleapis');
const path = require('path');
const fs = require('fs');

const KEY_PATH = path.join(__dirname, 'sodium-surf-501215-u3-de64e936ad39.json');
const TOKEN_PATH = path.join(__dirname, 'drive_tokens.json');
const ROOT_FOLDER_NAME = 'LensFlow';
const REDIRECT_URI = process.env.DRIVE_REDIRECT || 'http://localhost:3000/api/drive/callback';

let authClient = null;
let rootFolderId = null;
let authPromise = null;

async function getAuthClient() {
  if (authClient) return authClient;
  if (authPromise) return authPromise;
  authPromise = _initAuth();
  return authPromise;
}

async function _initAuth() {
  if (fs.existsSync(TOKEN_PATH)) {
    try {
      const tokens = JSON.parse(fs.readFileSync(TOKEN_PATH, 'utf-8'));
      if (tokens.refresh_token && tokens.client_id && tokens.client_secret) {
        const oauth = new google.auth.OAuth2(tokens.client_id, tokens.client_secret, tokens.redirect_uri || REDIRECT_URI);
        oauth.setCredentials({ refresh_token: tokens.refresh_token });
        authClient = oauth;
        return authClient;
      }
    } catch (e) { console.error('OAuth2 token load failed:', e.message); }
  }
  if (fs.existsSync(KEY_PATH)) {
    try {
      const sa = new google.auth.GoogleAuth({
        keyFile: KEY_PATH,
        scopes: ['https://www.googleapis.com/auth/drive.file'],
      });
      authClient = sa;
      return authClient;
    } catch (e) { console.error('Service account auth failed:', e.message); }
  }
  throw new Error('No Google Drive auth method available');
}

function getDrive() {
  if (!authClient) throw new Error('Auth not initialized. Call getAuthClient() first.');
  return google.drive({ version: 'v3', auth: authClient });
}

async function getOrCreateRootFolder() {
  await getAuthClient();
  if (rootFolderId) return rootFolderId;
  const drive = getDrive();
  const search = await drive.files.list({
    q: `name='${ROOT_FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
    fields: 'files(id)',
    spaces: 'drive',
  });
  if (search.data.files.length > 0) { rootFolderId = search.data.files[0].id; return rootFolderId; }
  const created = await drive.files.create({
    requestBody: { name: ROOT_FOLDER_NAME, mimeType: 'application/vnd.google-apps.folder' },
    fields: 'id',
  });
  rootFolderId = created.data.id;
  return rootFolderId;
}

async function getOrCreateAlbumFolder(albumId, albumTitle) {
  await getAuthClient();
  const drive = getDrive();
  const parentId = await getOrCreateRootFolder();
  const folderName = `${albumId} - ${albumTitle.replace(/[^a-zA-Z0-9а-яА-ЯёЁ\s-]/g, '_')}`;
  const search = await drive.files.list({
    q: `name='${folderName}' and '${parentId}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false`,
    fields: 'files(id)',
    spaces: 'drive',
  });
  if (search.data.files.length > 0) return search.data.files[0].id;
  const created = await drive.files.create({
    requestBody: { name: folderName, mimeType: 'application/vnd.google-apps.folder', parents: [parentId] },
    fields: 'id',
  });
  return created.data.id;
}

async function uploadPhoto(localPath, fileName, albumId, albumTitle) {
  await getAuthClient();
  const drive = getDrive();
  const folderId = await getOrCreateAlbumFolder(albumId, albumTitle);
  const res = await drive.files.create({
    requestBody: { name: fileName, parents: [folderId] },
    media: { body: fs.createReadStream(localPath) },
    fields: 'id, webViewLink',
  });
  return { driveFileId: res.data.id, webViewLink: res.data.webViewLink };
}

async function getFileStream(fileId) {
  await getAuthClient();
  const drive = getDrive();
  const res = await drive.files.get({ fileId, alt: 'media' }, { responseType: 'stream' });
  return res.data;
}

async function deleteFile(fileId) {
  await getAuthClient();
  const drive = getDrive();
  await drive.files.delete({ fileId });
}

async function deleteFolder(folderId) {
  await getAuthClient();
  const drive = getDrive();
  await drive.files.delete({ fileId: folderId });
}

async function findAlbumFolder(albumId, albumTitle) {
  await getAuthClient();
  const drive = getDrive();
  const parentId = await getOrCreateRootFolder();
  const folderName = `${albumId} - ${albumTitle.replace(/[^a-zA-Z0-9а-яА-ЯёЁ\s-]/g, '_')}`;
  const search = await drive.files.list({
    q: `name='${folderName}' and '${parentId}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false`,
    fields: 'files(id)',
    spaces: 'drive',
  });
  return search.data.files.length > 0 ? search.data.files[0].id : null;
}

function saveTokens(tokens, clientId, clientSecret) {
  const data = { ...tokens, client_id: clientId, client_secret: clientSecret, redirect_uri: REDIRECT_URI };
  fs.writeFileSync(TOKEN_PATH, JSON.stringify(data, null, 2));
  authClient = null;
  authPromise = null;
  console.log('Drive OAuth2 tokens saved');
}

module.exports = {
  getAuthClient, getOrCreateRootFolder, getOrCreateAlbumFolder,
  uploadPhoto, getFileStream, deleteFile, deleteFolder, findAlbumFolder, saveTokens,
};
