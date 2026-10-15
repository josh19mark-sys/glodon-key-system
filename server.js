const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);
app.use(cors());
app.use(express.json({ limit: "10kb" }));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: "Demasiadas solicitudes. Inténtalo más tarde."
    }
});

app.use("/api/", apiLimiter);

const KEY_LIFETIME_HOURS = 12;

async function initializeDatabase() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS glodon_keys (
            key TEXT PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at TIMESTAMPTZ NOT NULL,
            revoked BOOLEAN NOT NULL DEFAULT FALSE
        );
    `);

    console.log("Base de datos Neon conectada.");
}

function generateKey() {
    const characters = crypto.randomBytes(12).toString("hex");
    const groups = characters.match(/.{4}/g);

    return "[Glodon] " + groups.join("-");
}

app.get("/", (req, res) => {
    res.json({
        service: "Glodon Hub Key System",
        status: "online"
    });
});

app.get("/api/health", async (req, res) => {
    try {
        await pool.query("SELECT 1");

        res.json({
            status: "online",
            database: "connected"
        });
    } catch (error) {
        console.error("Health check error:", error.message);

        res.status(503).json({
            status: "error",
            database: "unavailable"
        });
    }
});

app.post("/api/keys/create", async (req, res) => {
    try {
        const expiresAt = new Date(
            Date.now() + KEY_LIFETIME_HOURS * 60 * 60 * 1000
        );

        let key;
        let saved = false;

        for (let attempt = 0; attempt < 3; attempt++) {
            key = generateKey();

            try {
                await pool.query(
                    `INSERT INTO glodon_keys (key, expires_at)
                     VALUES ($1, $2)`,
                    [key, expiresAt]
                );

                saved = true;
                break;
            } catch (error) {
                if (error.code !== "23505") {
                    throw error;
                }
            }
        }

        if (!saved) {
            return res.status(500).json({
                error: "No se pudo generar una key. Inténtalo de nuevo."
            });
        }

        res.status(201).json({
            success: true,
            key,
            expiresAt: expiresAt.toISOString(),
            expiresInHours: KEY_LIFETIME_HOURS
        });
    } catch (error) {
        console.error("Create key error:", error.message);

        res.status(500).json({
            error: "Error al generar la key."
        });
    }
});

app.post("/api/keys/validate", async (req, res) => {
    try {
        const key = req.body?.key;

        if (
            typeof key !== "string" ||
            !/^\[Glodon\] [a-f0-9]{4}(?:-[a-f0-9]{4}){5}$/.test(key)
        ) {
            return res.status(400).json({
                valid: false,
                error: "Formato de key inválido."
            });
        }

        const result = await pool.query(
            `SELECT key, expires_at, revoked
             FROM glodon_keys
             WHERE key = $1
             LIMIT 1`,
            [key]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                valid: false,
                error: "Key inexistente."
            });
        }

        const record = result.rows[0];

        if (record.revoked) {
            return res.status(403).json({
                valid: false,
                error: "Esta key ha sido revocada."
            });
        }

        if (new Date(record.expires_at).getTime() <= Date.now()) {
            return res.status(403).json({
                valid: false,
                error: "Esta key ha vencido."
            });
        }

        return res.json({
            valid: true,
            message: "Key Glodon aprobada.",
            expiresAt: new Date(record.expires_at).toISOString()
        });
    } catch (error) {
        console.error("Validate key error:", error.message);

        res.status(500).json({
            valid: false,
            error: "Error al validar la key."
        });
    }
});

app.use((req, res) => {
    res.status(404).json({
        error: "Ruta no encontrada."
    });
});

async function startServer() {
    try {
        if (!process.env.DATABASE_URL) {
            throw new Error(
                "Falta configurar la variable DATABASE_URL en Render."
            );
        }

        await initializeDatabase();

        app.listen(PORT, "0.0.0.0", () => {
            console.log(`Glodon Key System activo en el puerto ${PORT}.`);
        });
    } catch (error) {
        console.error("No se pudo iniciar el servidor:", error.message);
        process.exit(1);
    }
}

startServer();