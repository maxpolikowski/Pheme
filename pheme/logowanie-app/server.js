const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();

// --- KONFIGURACJA ---
const SECRET = "tajny_klucz";
const DB_FILE = "users.json";
const SECTIONS_FILE = "sections.json";

app.use(express.json());
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

// Serwowanie plików statycznych (aby wygenerowane .html były dostępne)
app.use(express.static(__dirname));

// 🔒 Limiter IP
const loginLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 1000,
    message: "Zbyt wiele prób logowania. Spróbuj później.",
    standardHeaders: true,
    legacyHeaders: false,
});

// --- INICJALIZACJA BAZY ---
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, "[]");
if (!fs.existsSync(SECTIONS_FILE)) fs.writeFileSync(SECTIONS_FILE, "[]");

function loadUsers() {
    try { return JSON.parse(fs.readFileSync(DB_FILE, "utf-8")); } 
    catch (err) { return []; }
}
function saveUsers(users) { fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2)); }

function loadSections() {
    try { return JSON.parse(fs.readFileSync(SECTIONS_FILE, "utf-8")); } 
    catch (err) { return []; }
}
function saveSections(sections) { fs.writeFileSync(SECTIONS_FILE, JSON.stringify(sections, null, 2)); }

// --- MIDDLEWARE ---

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

function admin(req, res, next) {
    if (req.user.role !== "admin") return res.status(403).send("Brak dostępu");
    next();
}

// --- ENDPOINTY UŻYTKOWNIKÓW ---

app.post("/register", async (req, res) => {
    try {
        const { username, password, name } = req.body;
        let users = loadUsers();
        if (users.find(u => u.username === username)) return res.status(400).send("Użytkownik już istnieje");
        const hash = await bcrypt.hash(password, 10);
        users.push({ username, password: hash, name: name || "", role: "user" });
        saveUsers(users);
        res.send("Zarejestrowano!");
    } catch (e) { res.status(500).send("Błąd serwera"); }
});

app.post("/login", loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    let users = loadUsers();
    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).send("Brak użytkownika");
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).send("Złe hasło");
    const token = jwt.sign({ username: user.username, role: user.role }, SECRET, { expiresIn: "7d" });
    res.json({ token });
});

app.get("/profil", auth, (req, res) => {
    const users = loadUsers();
    const user = users.find(u => u.username === req.user.username);
    if (!user) return res.status(404).send("User not found");
    res.json({ username: user.username, name: user.name || "", role: user.role });
});

app.post("/update-profile", auth, async (req, res) => {
    const { newName, oldPassword, newPassword } = req.body;
    let users = loadUsers();
    const user = users.find(u => u.username === req.user.username);
    if (!user) return res.status(404).json({ message: "Użytkownik nie istnieje" });
    if (newName && newName.trim() !== "") user.name = newName;
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

function generujSzablonSekcji(nazwa, kod) {
    return `
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <title>Sekcja - ${nazwa}</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f5f5f5; text-align: center; padding: 50px; }
        .card { background: white; padding: 30px; border-radius: 15px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); display: inline-block; min-width: 300px; }
        h1 { color: #00ce52; }
        .code { font-weight: bold; color: #555; font-size: 1.2rem; background: #eee; padding: 10px; border-radius: 5px; }
        .back-link { margin-top: 20px; display: block; color: #333; text-decoration: none; font-weight: bold; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Sekcja: ${nazwa}</h1>
        <p>Kod dołączenia:</p>
        <div class="code">${kod}</div>
        <hr>
        <p>Witaj w panelu sekcji!</p>
        <a href="sekcje.html" class="back-link">← Wróć do listy sekcji</a>
    </div>
</body>
</html>`;
}

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
        members: [{ username: req.user.username, role: "nauczyciel" }] 
    };

    sections.push(newSection);
    saveSections(sections);

    // ZAMIAST TWORZYĆ PLIK, PO PROSTU POTWIERDZAMY SUKCES
    res.json({ 
        message: "Sekcja utworzona pomyślnie!",
        code: code 
    });
});

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
app.get("/section-members/:code", auth, (req, res) => {
    const sections = loadSections();
    const section = sections.find(s => s.code === req.params.code);

    if (!section) return res.status(404).json({ message: "Nie ma takiej sekcji" });

    // Sprawdzamy, czy osoba pytająca należy do sekcji
    const isMember = section.members.some(m => m.username === req.user.username);
    if (!isMember) return res.status(403).json({ message: "Brak dostępu" });

    // Pobieramy wszystkich użytkowników, żeby wyciągnąć ich prawdziwe imiona
    const allUsers = loadUsers();

    // Mapujemy członków sekcji tak, aby dołączyć ich pole 'name'
    const membersWithNames = section.members.map(member => {
        const userDetails = allUsers.find(u => u.username === member.username);
        return {
            username: member.username,
            name: userDetails ? userDetails.name : "Brak imienia", // Tu wyciągamy imię
            role: member.role
        };
    });

    res.json(membersWithNames);
});
app.post("/promote-to-teacher", auth, (req, res) => {
    const { code, targetUsername } = req.body;
    let sections = loadSections();
    const section = sections.find(s => s.code === code);

    if (!section) return res.status(404).json({ message: "Nie znaleziono sekcji" });

    // Sprawdzamy, czy osoba wykonująca akcję jest nauczycielem w tej sekcji
    const requester = section.members.find(m => m.username === req.user.username);
    if (!requester || requester.role !== "nauczyciel") {
        return res.status(403).json({ message: "Tylko nauczyciel może dodawać innych nauczycieli" });
    }

    // Znajdujemy osobę, którą chcemy awansować
    const targetMember = section.members.find(m => m.username === targetUsername);
    if (!targetMember) return res.status(404).json({ message: "Użytkownik nie należy do tej sekcji" });

    // Zmieniamy rolę
    targetMember.role = "nauczyciel";
    
    saveSections(sections);
    res.json({ message: `Użytkownik ${targetUsername} został nauczycielem!` });
});
app.post("/reset", auth, admin, (req, res) => {
    let users = loadUsers();
    saveUsers(users.filter(u => u.role === "admin"));
    saveSections([]);
    res.send("Baza zresetowana");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Serwer Pheme działa na porcie " + PORT));