/**
 * Discord Scan Bot — Node.js
 * Escanea sitios web y muestra información en Discord.
 * Listo para Render (usa npm start).
 */

import tls from "tls";
import { URL } from "url";
import axios from "axios";
import * as cheerio from "cheerio";
import whois from "whois";
import express from "express";
import { Buffer } from "buffer";
import { Client, GatewayIntentBits, EmbedBuilder, REST, Routes } from "discord.js";

const DISCORD_TOKEN = process.env.DISCORD_BOT_TOKEN;
const TEST_GUILD_ID = process.env.TEST_GUILD_ID || null;

if (!DISCORD_TOKEN) {
  console.error("❌ FALTA: DISCORD_BOT_TOKEN en variables de entorno.");
  process.exit(1);
}

/* ---------------- Express Keep-Alive ---------------- */
const app = express();
app.get("/", (req, res) => res.send("✅ LookupBot running — status OK"));
app.get("/status", (req, res) => {
  const up = Math.floor(process.uptime());
  res.send(`✅ LookupBot online — uptime: ${up}s`);
});
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🌐 Keep-alive server listening on port ${PORT}`));

/* ---------------- Discord Client ---------------- */
const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent]
});

client.once("ready", () => console.log(`🤖 Bot listo: ${client.user.tag}`));

/* ---------------- Helpers ---------------- */
const SECURITY_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "x-xss-protection"
];

async function fetchUrl(url) {
  const t0 = Date.now();
  try {
    const res = await axios.get(url, {
      timeout: 15000,
      maxRedirects: 5,
      headers: { "User-Agent": "LookupBot/Discord (Node.js)" },
      validateStatus: () => true
    });
    return { res, elapsed: (Date.now() - t0) / 1000 };
  } catch (e) {
    return { error: e.message || String(e) };
  }
}

function getSslInfo(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, rejectUnauthorized: false, timeout: 8000 }, () => {
      try {
        const peer = socket.getPeerCertificate(true);
        if (!peer || Object.keys(peer).length === 0) {
          resolve({ error: "no certificate returned" });
        } else {
          resolve({
            issuer: peer.issuer || null,
            valid_from: peer.valid_from || null,
            valid_to: peer.valid_to || null,
            subject: peer.subject || null
          });
        }
      } catch (err) {
        resolve({ error: err.message });
      } finally {
        socket.end();
      }
    });
    socket.on("error", (e) => resolve({ error: e.message }));
  });
}

function whoisPromise(hostname) {
  return new Promise((resolve) => {
    try {
      whois.lookup(hostname, (err, data) => {
        if (err) return resolve({ error: err.message });
        resolve({ raw: data });
      });
    } catch (e) {
      resolve({ error: e.message });
    }
  });
}

function analyzeSecurityHeaders(headers) {
  const out = {};
  for (const h of SECURITY_HEADERS) out[h] = headers[h] || null;
  out.csp = !!headers["content-security-policy"];
  out.hsts = !!headers["strict-transport-security"];
  return out;
}

function detectCaptcha(html) {
  const s = (html || "").toLowerCase();
  return !!(s.includes("recaptcha") || s.includes("hcaptcha") || s.includes("captcha"));
}

/* ---------------- Detector principal ---------------- */
async function performScan(urlRaw) {
  let normalized = urlRaw;
  if (!/^https?:\/\//i.test(urlRaw)) normalized = "https://" + urlRaw;
  const hostname = new URL(normalized).hostname;

  const main = await fetchUrl(normalized);
  if (main.error) return { error: main.error };
  const res = main.res;
  const html = typeof res.data === "string" ? res.data : "";
  const headers = res.headers || {};

  // SSL y WHOIS
  const ssl = await getSslInfo(hostname);
  const who = await whoisPromise(hostname);

  // Detección básica de CMS, pagos, captcha
  const s = html.toLowerCase();
  let cms = "Desconocido";
  if (s.includes("wp-content") || s.includes("wordpress")) cms = "WordPress";
  else if (s.includes("cdn.shopify") || s.includes("myshopify.com")) cms = "Shopify";
  else if (s.includes("magento")) cms = "Magento";

  const payments = [];
  if (s.includes("stripe")) payments.push("Stripe");
  if (s.includes("paypal")) payments.push("PayPal");
  if (s.includes("square")) payments.push("Square");
  if (s.includes("revolut")) payments.push("Revolut");
  if (s.includes("woocommerce")) payments.push("WooCommerce");

  const result = {
    site: normalized,
    status: res.status,
    redirects: res.request?.res?.responseUrl || "None",
    response_time: main.elapsed.toFixed(2),
    page_size: `${(Buffer.byteLength(html, "utf8") / 1024).toFixed(2)} KB`,
    security_headers: analyzeSecurityHeaders(headers),
    ssl,
    cms,
    payments: payments.length ? payments.join(", ") : "None",
    captcha: detectCaptcha(html) ? "Detected" : "No captcha",
    whois: who,
    timestamp: new Date().toISOString()
  };
  return result;
}

/* ---------------- Formato del resultado ---------------- */
function buildLookupText(r) {
  return [
    "┏━━━━━━━⍟",
    "┃ 𝐋𝐨𝐨𝐤𝐮𝐩 𝐑𝐞𝐬𝐮𝐥𝐭 ✅",
    "┗━━━━━━━━━━━⊛",
    "",
    `[⌬] 𝐒𝐢𝐭𝐞↣ ${r.site}`,
    `[⌬] 𝐑𝐞𝐝𝐢𝐫𝐞𝐜𝐭𝐬↣ ${r.redirects}`,
    `[⌬] 𝐒𝐒𝐋↣ Issuer: ${r.ssl?.issuer?.O || "Unknown"}, Expires: ${r.ssl?.valid_to || "Unknown"}`,
    `[⌬] 𝐒𝐞𝐜𝐮𝐫𝐢𝐭𝐲 𝐇𝐞𝐚𝐝𝐞𝐫𝐬↣ CSP: ${r.security_headers.csp}, HSTS: ${r.security_headers.hsts}`,
    `[⌬] 𝐏𝐚𝐲𝐦𝐞𝐧𝐭 𝐆𝐚𝐭𝐞𝐰𝐚𝐲𝐬↣ ${r.payments}`,
    `[⌬] 𝐂𝐚𝐩𝐭𝐜𝐡𝐚↣ ${r.captcha}`,
    "━━━━━━━━━━━━━━━━━━━",
    `[⌬] 𝐈𝐧𝐛𝐮𝐢𝐥𝐭 𝐒𝐲𝐬𝐭𝐞𝐦↣ ${r.cms}`,
    `[⌬] 𝐒𝐭𝐚𝐭𝐮𝐬↣ ${r.status}`,
    `[⌬] 𝐏𝐚𝐠𝐞 𝐒𝐢𝐳𝐞↣ ${r.page_size}`,
    `[⌬] 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 𝐓𝐢𝐦𝐞↣ ${r.response_time} sec`,
    "━━━━━━━━━━━━━━━━━━━",
    `[⌬] 𝐓𝐢𝐦𝐞↣ ${r.timestamp}`,
  ].join("\n");
}

/* ---------------- Comandos Discord ---------------- */
const slashCommandData = [
  {
    name: "scan",
    description: "Escanea una URL (lookup básico)",
    options: [{ name: "url", description: "URL a escanear", type: 3, required: true }]
  }
];

client.once("ready", async () => {
  const rest = new REST({ version: "10" }).setToken(DISCORD_TOKEN);
  try {
    if (TEST_GUILD_ID) {
      await rest.put(Routes.applicationGuildCommands(client.user.id, TEST_GUILD_ID), { body: slashCommandData });
      console.log("✅ Slash command registrado (guild).");
    } else {
      await rest.put(Routes.applicationCommands(client.user.id), { body: slashCommandData });
      console.log("✅ Slash command registrado globalmente.");
    }
  } catch (e) {
    console.warn("⚠️ No se pudo registrar slash commands:", e.message);
  }
});

client.on("interactionCreate", async (interaction) => {
  if (!interaction.isCommand() || interaction.commandName !== "scan") return;
  const url = interaction.options.getString("url");
  await interaction.deferReply();

  try {
    const data = await performScan(url);
    if (data.error) return interaction.editReply(`❌ Error: ${data.error}`);
    const txt = buildLookupText(data);
    const jsonBuf = Buffer.from(JSON.stringify(data, null, 2), "utf8");
    await interaction.editReply({ content: "```" + txt + "```", files: [{ attachment: jsonBuf, name: "scan_result.json" }] });
  } catch (e) {
    await interaction.editReply(`❌ Error en el escaneo: ${e.message}`);
  }
});

client.on("messageCreate", async (msg) => {
  if (msg.author.bot) return;
  if (!msg.content.startsWith("!scan ")) return;

  const url = msg.content.split(" ")[1];
  if (!url) return msg.reply("Uso: `!scan <url>`");

  await msg.channel.sendTyping();
  try {
    const data = await performScan(url);
    if (data.error) return msg.reply(`❌ Error: ${data.error}`);
    const txt = buildLookupText(data);
    const jsonBuf = Buffer.from(JSON.stringify(data, null, 2), "utf8");
    await msg.reply({ content: "```" + txt + "```", files: [{ attachment: jsonBuf, name: "scan_result.json" }] });
  } catch (e) {
    await msg.reply(`❌ Error: ${e.message}`);
  }
});

/* ---------------- Login ---------------- */
client.login(DISCORD_TOKEN).catch((err) => console.error("Error al iniciar sesión:", err));

/* ---------------- Error handlers ---------------- */
process.on("unhandledRejection", (r) => console.error("⚠️ Unhandled rejection:", r));
process.on("uncaughtException", (e) => console.error("⚠️ Uncaught exception:", e));
