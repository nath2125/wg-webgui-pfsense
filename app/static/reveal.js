"use strict";
// Public reveal page: build the QR + download from the server-rendered config.
(function () {
  var pre = document.getElementById("conf");
  var conf = pre ? pre.textContent : "";
  var filename = document.querySelector("[data-filename]");
  filename = (filename && filename.getAttribute("data-filename")) || "wg.conf";

  // QR
  var el = document.getElementById("qr");
  try {
    var qr = qrcode(0, "M");
    qr.addData(conf);
    qr.make();
    var img = new Image();
    img.src = qr.createDataURL(5, 2);
    img.alt = "WireGuard config QR";
    el.appendChild(img);
  } catch (e) {
    el.textContent = "(config too large for QR — use the download)";
  }

  // Download
  var btn = document.getElementById("download-btn");
  if (btn) {
    btn.addEventListener("click", function () {
      var blob = new Blob([conf], { type: "text/plain" });
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    });
  }
})();
