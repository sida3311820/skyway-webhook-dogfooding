// server.js
import express from "express";
import { createHmac, timingSafeEqual } from "node:crypto";

const app = express();
app.use(express.json());

// 先ほど生成した署名用共通鍵をここに設定
const SIGNING_SECRET = "5c94c87e3c55d5f23cacec8f64307c6ef4abc11db94ed92aa62ffa62760f05fa";

// 署名検証関数（検証リクエスト用）
function verifySignature(signingSecret, body, timestamp, receivedHex) {
  // 1) タイムスタンプ検証（リプレイ防止）
  const tsNum = Number(timestamp);
  if (!Number.isFinite(tsNum)) return false;
  const ageMs = Math.abs(Date.now() - tsNum * 1000);
  // クイックスタートでは60秒の許容範囲を設定
  if (ageMs > 60 * 1000) {
    return false;
  }

  // 2) HMAC を計算
  const payload = `${body}${String(timestamp)}`;
  const expectedHex = createHmac("sha256", signingSecret).update(payload).digest("hex");

  // 3) 比較（暗号学的に安全な比較）
  const expBuf = Buffer.from(expectedHex, "hex");
  const recBuf = Buffer.from(receivedHex, "hex");
  if (expBuf.length !== recBuf.length) return false;

  return timingSafeEqual(expBuf, recBuf);
}

// Webhookエンドポイント
app.post("/webhook", (req, res) => {
  const body = JSON.stringify(req.body);
  const timestamp = req.headers["x-skyway-request-timestamp"];
  const signature = req.headers["x-skyway-signature"];

  console.log("Received request:", body);

  // 検証リクエスト処理
  if (req.body.type === "WEBHOOK_URL_VERIFICATION") {
    const challenge = req.body.data?.challenge;
    
    // 必要なパラメータの存在チェック
    if (!challenge || !timestamp || !signature) {
      console.log("❌ Bad Request: Missing required parameters");
      return res.status(400).send("Bad Request: Missing required parameters");
    }

    // 署名検証を実行
    if (verifySignature(SIGNING_SECRET, body, timestamp, signature)) {
      console.log("✅ Verification successful");
      res.status(200).send(challenge);
      return;
    } else {
      console.log("❌ Verification failed: Invalid signature");
      return res.status(400).send("Bad Request: Invalid signature");
    }
  }
         
  // その他のwebhookリクエスト
  // 必要なパラメータの存在チェック
  if (!timestamp || !signature) {
    console.log("❌ Missing signature headers");
    return res.status(400).send("Bad Request: Missing signature headers");
  }

  if (!verifySignature(SIGNING_SECRET, body, timestamp, signature)) {
    console.log("❌ Signature verification failed");
    return res.status(400).send("Bad Request: Invalid signature");
  }
  
  res.status(200).send("OK");

  // 任意のイベント処理
  console.log("✅ Event received:", req.body.type);

});
app.listen(3000, () => {
  console.log("Webhook server running on port 3000");
});