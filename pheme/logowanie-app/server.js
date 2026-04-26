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
const SECTIONS_FILE = "sections.json";

// 🔒 Limiter IP (1000 prób na godzinę)
const loginLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 1000,
    message: "Zbyt wiele prób logowania. Spróbuj później.",
    standardHeaders: true,
    legacyHeaders: false,
});

// --- INICJALIZACJA PLIKÓW BAZY ---
if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, "[]");
}
if (!fs.existsSync(SECTIONS_FILE)) {
    fs.writeFileSync(SECTIONS_FILE, "[]");
}

// --- FUNKCJE POMOCNICZE (USERS) ---
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

// --- FUNKCJE POMOCNICZE (SECTIONS) ---
function loadSections() {
    try {
        return JSON.parse(fs.readFileSync(SECTIONS_FILE, "utf-8"));
    } catch (err) {
        return [];
    }
}

function saveSections(sections) {
    fs.writeFileSync(SECTIONS_FILE, JSON.stringify(sections, null, 2));
}

// --- MIDDLEWARE ---

// Autoryzacja
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

// Admin Only
function admin(req, res, next) {
    if (req.user.role !== "admin") return res.status(403).send("Brak dostępu");
    next();
}

// --- ENDPOINTY UŻYTKOWNIKÓW ---

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

// PROFIL
app.get("/profil", auth, (req, res) => {
    const users = loadUsers();
    const user = users.find(u => u.username === req.user.username);
    if (!user) return res.status(404).send("User not found");

    res.json({
        username: user.username,
        name: user.name || "",
        role: user.role
    });
});

// AKTUALIZACJA PROFILU
app.post("/update-profile", auth, async (req, res) => {
    const { newName, oldPassword, newPassword } = req.body;
    let users = loadUsers();
    const user = users.find(u => u.username === req.user.username);

    if (!user) return res.status(404).json({ message: "Użytkownik nie istnieje" });

    if (newName && newName.trim() !== "") {
        user.name = newName;
    }

    if (newPassword && newPassword.trim() !== "") {
        if (!oldPassword) return res.status(400).json({ message: "Podaj stare hasło" });
        const passwordMatch = await bcrypt.compare(oldPassword, user.password);
        if (!passwordMatch) return res.status(401).json({ message: "Stare hasło nieprawidłowe" });
        user.password = await bcrypt.hash(newPassword, 10);
    }

    saveUsers(users);
    res.json({ message: "Pomyślnie zaktualizowano profil" });
});

// --- ENDPOINTY SEKCJI ---

// TWORZENIE SEKCJI (ADMIN)
app.post("/create-section", auth, admin, (req, res) => {
    const { name, code } = req.body;
    let sections = loadSections();

    if (sections.find(s => s.code === code)) {
        return res.status(400).json({ message: "Sekcja o tym kodzie już istnieje" });
    }

    const newSection = {
        name,
        code,
        creator: req.user.username,
        members: [{ username: req.user.username, role: "admin" }] 
    };

    sections.push(newSection);
    saveSections(sections);
    res.json({ message: "Sekcja została utworzona!" });
});

// DOŁĄCZANIE DO SEKCJI
app.post("/join-section", auth, (req, res) => {
    const { code } = req.body;
    let sections = loadSections();

    const section = sections.find(s => s.code === code);
    if (!section) return res.status(404).json({ message: "Zły kod sekcji" });

    if (section.members.find(m => m.username === req.user.username)) {
        return res.status(400).json({ message: "Już tu jesteś!" });
    }

    section.members.push({ username: req.user.username, role: "user" });
    saveSections(sections);
    res.json({ message: "Dołączono do sekcji: " + section.name });
});

// LISTA MOICH SEKCJI
app.get("/moje-sekcje", auth, (req, res) => {
    const sections = loadSections();
    const mySections = sections
        .filter(s => s.members.some(m => m.username === req.user.username))
        .map(s => ({
            name: s.name,
            kod: s.code,
            rola: s.members.find(m => m.username === req.user.username).role
        }));
    res.json(mySections);
});

// RESET BAZY (ADMIN)
app.post("/reset", auth, admin, (req, res) => {
    let users = loadUsers();
    const adminsOnly = users.filter(u => u.role === "admin");
    saveUsers(adminsOnly);
    saveSections([]); // Czyścimy też sekcje
    res.send("Baza zresetowana");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("Serwer Pheme działa na porcie " + PORT);
});