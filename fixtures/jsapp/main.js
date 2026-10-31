const {app, BrowserWindow, ipcMain} = require('electron');
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({width: 1024, webPreferences: {preload: path.join(__dirname, 'preload.js')}});
  win.loadFile('index.html');
}

ipcMain.handle('ping', () => 'pong');
app.whenReady().then(createWindow);
