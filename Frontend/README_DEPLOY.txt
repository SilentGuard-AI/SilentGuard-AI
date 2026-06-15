SilentGuard AI - Prettier Pipeline Demo Build

Changes in this version:
- Replaced the previous simple demo with a more polished interactive pipeline preview.
- Removed the "Safe for resume mode: no AWS runtime cost" text from the page.
- Added explicit automatic-disconnect behavior:
  "Guardian alerted + call hung up"
  "Call automatically disconnected to protect the user."
- Removed the live Amazon Connect widget script from index.html to avoid a stale/broken phone widget.

Deploy:
Upload this folder's contents to the existing static website bucket / CloudFront origin.

Files:
- index.html
- asset-manifest.json
- static/js/main.13b5d002.js
- static/js/main.13b5d002.js.LICENSE.txt
- static/js/main.13b5d002.js.map

Note:
This is a patched production build. For long-term maintenance, add the demo in src/App.js and rebuild normally.
