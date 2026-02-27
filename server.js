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
    const macKey = expandedKey.slice(48, 80);

    const fileData = encryptedBuffer.slice(0, encryptedBuffer.length - 10);
    const mac = encryptedBuffer.slice(encryptedBuffer.length - 10);

    const computedMac = crypto
      .createHmac("sha256", macKey)
      .update(Buffer.concat([iv, fileData]))
      .digest()
      .slice(0, 10);

    if (!computedMac.equals(mac)) {
      throw new Error("MAC inválido");
    }

    const decipher = crypto.createDecipheriv("aes-256-cbc", cipherKey, iv);
    decipher.setAutoPadding(true);

    const decrypted = Buffer.concat([
      decipher.update(fileData),
      decipher.final(),
    ]);

    res.setHeader("Content-Type", "audio/ogg");
    res.send(decrypted);

  } catch (err) {
    console.error("Erro real:", err);
    res.status(500).json({ error: "Erro ao descriptografar áudio" });
  }
});
