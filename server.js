const express = require("express");
const axios = require("axios");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "10mb" }));

function hkdf(mediaKey, length, info) {
  const salt = Buffer.alloc(32, 0);
  const prk = crypto.createHmac("sha256", salt).update(mediaKey).digest();

  let prev = Buffer.alloc(0);
  let output = Buffer.alloc(0);
  let i = 0;

  while (output.length < length) {
    i++;
    const hmac = crypto.createHmac("sha256", prk);
    hmac.update(Buffer.concat([prev, Buffer.from(info), Buffer.from([i])]));
    prev = hmac.digest();
    output = Buffer.concat([output, prev]);
  }

  return output.slice(0, length);
}

app.post("/decrypt-audio", async (req, res) => {
  try {
    const { mediaUrl, mediaKey } = req.body;

    if (!mediaUrl || !mediaKey) {
      return res.status(400).json({ error: "mediaUrl e mediaKey são obrigatórios" });
    }

    const response = await axios.get(mediaUrl, {
      responseType: "arraybuffer",
    });

    const encryptedBuffer = Buffer.from(response.data);
    const mediaKeyBuffer = Buffer.from(mediaKey, "base64");

    const expandedKey = hkdf(mediaKeyBuffer, 112, "WhatsApp Audio Keys");

    const iv = expandedKey.slice(0, 16);
    const cipherKey = expandedKey.slice(16, 48);

    const fileData = encryptedBuffer.slice(0, encryptedBuffer.length - 10);

    const decipher = crypto.createDecipheriv("aes-256-cbc", cipherKey, iv);
    const decrypted = Buffer.concat([
      decipher.update(fileData),
      decipher.final(),
    ]);

    res.setHeader("Content-Type", "audio/ogg");
    res.send(decrypted);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao descriptografar áudio" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Decrypt server rodando na porta " + PORT);
});