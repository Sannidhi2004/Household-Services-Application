const mix = require("laravel-mix");

mix
  .js("frontend/src/main.js", "frontend/dist")
  .vue()
  .setPublicPath("frontend/dist");
