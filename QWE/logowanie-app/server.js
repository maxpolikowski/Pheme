const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json());
app.use(cors());

const SECRET = "tajny_klucz";
const DB_FILE = "users.json";

// 1. Konfiguracja limitera IP (Max 1000 prób logowania na 15 min z jednego IP)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 1000,
    message: "Zbyt wiele prób logowania z tego adresu IP. Spróbuj za 15 minut.",
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

// REJESTRACJA (z limitem wielkości pliku)
app.post("/register", async (req, res) => {
    try {
        const stats = fs.statSync(DB_FILE);
        if (stats.size > 1000000) return res.status(400).send("Baza danych jest pełna");

        const { username, password } = req.body;
        let users = loadUsers();

        if (users.find(u => u.username === username)) return res.status(400).send("Użytkownik już istnieje");

        const hash = await bcrypt.hash(password, 10);
        users.push({
            username,
            password: hash,
            role: "user",
            loginAttempts: 0,
            lockUntil: null
        });

        saveUsers(users);
        res.send("Zarejestrowano!");
    } catch (e) {
        res.status(500).send("Błąd serwera");
    }
});

// LOGOWANIE (z limiterem IP i blokadą konta)
app.post("/login", loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    let users = loadUsers();

    const userIndex = users.findIndex(u => u.username === username);
    if (userIndex === -1) return res.status(400).send("Brak użytkownika");

    const user = users[userIndex];

    // Sprawdź blokadę czasową konta
    if (user.lockUntil && user.lockUntil > Date.now()) {
        const remaining = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60);
        return res.status(403).send(`Konto zablokowane. Spróbuj za ${remaining} min.`);
    }

    const ok = await bcrypt.compare(password, user.password);

    if (!ok) {
        user.loginAttempts = (user.loginAttempts || 0) + 1;
        
        if (user.loginAttempts >= 5) {
            user.lockUntil = Date.now() + 15 * 60 * 1000; // Blokada 15 min
            user.loginAttempts = 0;
            saveUsers(users);
            return res.status(403).send("Zbyt wiele prób. Konto zablokowane na 15 minut.");
        }

        saveUsers(users);
        return res.status(400).send(`Złe hasło. Pozostało prób: ${5 - user.loginAttempts}`);
    }

    // Sukces - czyścimy liczniki
    user.loginAttempts = 0;
    user.lockUntil = null;
    saveUsers(users);

    const token = jwt.sign(
        { username: user.username, role: user.role },
        SECRET,
        { expiresIn: "7d" }
    );

    res.json({ token });
});

// PROFIL
app.get("/profil", auth, (req, res) => {
    res.json(req.user);
});

// LISTA UŻYTKOWNIKÓW (ADMIN)
app.get("/users", auth, admin, (req, res) => {
    const users = loadUsers().map(u => ({ 
        username: u.username, 
        role: u.role, 
        isLocked: u.lockUntil && u.lockUntil > Date.now() 
    }));
    res.json(users);
});

// USUWANIE (ADMIN)
app.delete("/users/:username", auth, admin, (req, res) => {
    let users = loadUsers();
    const filtered = users.filter(u => u.username !== req.params.username);
    if (users.length === filtered.length) return res.status(404).send("Nie znaleziono");
    saveUsers(filtered);
    res.send(`Usunięto użytkownika ${req.params.username}`);
});

// RESET BAZY (ADMIN) - Zostawia adminów
app.post("/reset", auth, admin, (req, res) => {
    let users = loadUsers();
    const adminsOnly = users.filter(u => u.role === "admin");
    if (adminsOnly.length === 0) return res.status(500).send("Błąd: Brak admina w bazie!");
    saveUsers(adminsOnly);
    res.send(`Baza zresetowana. Pozostawiono ${adminsOnly.length} adminów.`);
});

app.listen(3000, () => console.log("Serwer Pheme działa na http://localhost:3000"));