const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json());
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

const SECRET = "tajny_klucz";
const DB_FILE = "users.json";

// 🔒 Limiter IP (1000 prób na godzinę)
const loginLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 1000,
    message: "Zbyt wiele prób logowania. Spróbuj później.",
    standardHeaders: true,
    legacyHeaders: false,
});

// Inicjalizacja pliku bazy
if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, "[]");
}

function loadUsers() {
    try {
        return JSON.parse(fs.readFileSync(DB_FILE, "utf-8"));
    } catch (err) {
        return [];
    }
}

function saveUsers(users) {
    fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

// Middleware: Autoryzacja
function auth(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.status(401).send("Brak tokena");

    const token = header.split(" ")[1];
    try {
        req.user = jwt.verify(token, SECRET);
        next();
    } catch {
        res.status(401).send("Zły token");
    }
}

// Middleware: Admin
function admin(req, res, next) {
    if (req.user.role !== "admin") return res.status(403).send("Brak dostępu");
    next();
}

// --- ENDPOINTY ---

// REJESTRACJA
app.post("/register", async (req, res) => {
    try {
        const { username, password, name } = req.body;
        let users = loadUsers();

        if (users.find(u => u.username === username)) {
            return res.status(400).send("Użytkownik już istnieje");
        }

        const hash = await bcrypt.hash(password, 10);

        users.push({
            username,
            password: hash,
            name: name || "",
            role: "user",
            loginAttempts: 0,
            attemptsWindowStart: Date.now()
        });

        saveUsers(users);
        res.send("Zarejestrowano!");
    } catch (e) {
        res.status(500).send("Błąd serwera");
    }
});

// LOGOWANIE
app.post("/login", loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    let users = loadUsers();

    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).send("Brak użytkownika");

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).send("Złe hasło");

    const token = jwt.sign(
        { username: user.username, role: user.role },
        SECRET,
        { expiresIn: "7d" }
    );

    res.json({ token });
});

// PROFIL (pobieranie danych)
app.get("/profil", auth, (req, res) => {
    const users = loadUsers();
    const user = users.find(u => u.username === req.user.username);

    res.json({
        username: user.username,
        name: user.name || "",
        role: user.role
    });
});

// 🔥 AKTUALIZACJA PROFILU (imię + hasło)
app.post("/update-profile", auth, async (req, res) => {
    const { newName, newPassword } = req.body;

    let users = loadUsers();
    const user = users.find(u => u.username === req.user.username);

    if (!user) {
        return res.status(404).json({ message: "Użytkownik nie istnieje" });
    }

    // Zmiana imienia
    if (newName && newName.trim() !== "") {
        user.name = newName;
    }

    // Zmiana hasła
    if (newPassword && newPassword.trim() !== "") {
        const hashed = await bcrypt.hash(newPassword, 10);
        user.password = hashed;
    }

    saveUsers(users);

    res.json({ message: "Pomyślnie zaktualizowano" });
});

// RESET BAZY (ADMIN)
app.post("/reset", auth, admin, (req, res) => {
    let users = loadUsers();
    const adminsOnly = users.filter(u => u.role === "admin");

    saveUsers(adminsOnly);
    res.send("Baza zresetowana");
});

// 🔥 Render wymaga PORT z env
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("Serwer działa na porcie " + PORT);
});
