app.post("/decrypt-audio", async (req, res) => {
  try {
    const { mediaUrl, mediaKey } = req.body;

    if (!mediaUrl || !mediaKey) {
      return res.status(400).json({ error: "mediaUrl e mediaKey são obrigatórios" });
    }

    console.log("Recebido request");
    console.log("mediaUrl:", mediaUrl);

    const response = await axios.get(mediaUrl, {
      responseType: "arraybuffer",
      timeout: 15000
    });

    const encryptedBuffer = Buffer.from(response.data);
    const mediaKeyBuffer = Buffer.from(mediaKey, "base64");

    console.log("mediaKey length:", mediaKeyBuffer.length);

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
      console.log("⚠️ MAC inválido — continuando mesmo assim");
    }

    let decrypted;

    try {
      const decipher = crypto.createDecipheriv("aes-256-cbc", cipherKey, iv);
      decipher.setAutoPadding(true);

      decrypted = Buffer.concat([
        decipher.update(fileData),
        decipher.final(),
      ]);

    } catch (decryptError) {
      console.error("Erro no decrypt interno:", decryptError);
      return res.status(500).json({ error: "Falha ao descriptografar buffer" });
    }

    res.setHeader("Content-Type", "audio/ogg");
    return res.send(decrypted);

  } catch (err) {
    console.error("Erro geral:", err);
    return res.status(500).json({ error: "Erro ao descriptografar áudio" });
  }
});
