module.exports = {
  apps: [{
    name: 'lensflow',
    script: 'server.js',
    env: {
      NODE_ENV: 'production',
      PORT: 3000,
    },
    max_memory_restart: '400M',
    exec_mode: 'fork',
    instances: 1,
  }]
};
