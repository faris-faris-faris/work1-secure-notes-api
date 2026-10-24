/**
 * Process entry point: build the app, listen, shut down cleanly.
 */
import { createApp } from './app.js';

function main() {
  let instance;
  try {
    instance = createApp();
  } catch (error) {
    console.error(`[api] refusing to start: ${error.message}`);
    process.exit(1);
  }

  const { app, config, close } = instance;
  const server = app.listen(config.port, config.host, () => {
    console.log(`[api] ${config.env} listening on http://${config.host}:${config.port}`);
    console.log(`[api] database: ${config.databasePath}`);
  });

  const shutdown = (signal) => {
    console.log(`[api] ${signal} received, shutting down`);
    server.close(() => {
      close();
      process.exit(0);
    });
    // Do not hang forever on a stuck keep-alive connection.
    setTimeout(() => process.exit(1), 5000).unref();
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main();
