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

app.post("/create-section", auth, admin, (req, res) => {
    const { name, code } = req.body;
    let sections = loadSections();
    if (sections.find(s => s.code === code)) return res.status(400).json({ message: "Sekcja już istnieje" });
    const newSection = {
        name,
        code,
        creator: req.user.username,
        members: [{ username: req.user.username, role: "nauczyciel" }],
        notes: [],
        feedbacks: []
    };
    sections.push(newSection);
    saveSections(sections);
    res.json({ message: "Sekcja utworzona pomyślnie!", code });
});

app.post("/join-section", auth, (req, res) => {
    const { code } = req.body;
    let sections = loadSections();
    const section = sections.find(s => s.code === code);
    if (!section) return res.status(404).json({ message: "Zły kod sekcji" });
    if (section.members.find(m => m.username === req.user.username)) return res.status(400).json({ message: "Już tu jesteś!" });
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
    if (!section.members.some(m => m.username === req.user.username)) return res.status(403).json({ message: "Brak dostępu" });
    const allUsers = loadUsers();
    const membersWithNames = section.members.map(member => {
        const userDetails = allUsers.find(u => u.username === member.username);
        return {
            username: member.username,
            name: userDetails ? userDetails.name : "Brak imienia",
            role: member.role
        };
    });
    res.json(membersWithNames);
});

// --- LEKCJE / NOTATKI ---

app.get("/section-notes/:code", auth, (req, res) => {
    const sections = loadSections();
    const section = sections.find(s => s.code === req.params.code);
    if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
    res.json(section.notes || []);
});

app.post("/add-note", auth, (req, res) => {
    const { code, lessonName, link1, link2 } = req.body;
    let sections = loadSections();
    const section = sections.find(s => s.code === code);
    if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
    const member = section.members.find(m => m.username === req.user.username);
    if (!member || (member.role !== "nauczyciel" && req.user.role !== "admin")) {
        return res.status(403).json({ message: "Brak uprawnień" });
    }
    if (!section.notes) section.notes = [];
    section.notes.push({ id: Date.now(), lessonName, link1, link2, date: new Date().toISOString().split('T')[0] });
    saveSections(sections);
    res.json({ message: "Notatka dodana!" });
});

app.delete("/delete-note/:code/:noteId", auth, (req, res) => {
    const { code, noteId } = req.params;
    let sections = loadSections();
    const section = sections.find(s => s.code === code);
    if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
    const member = section.members.find(m => m.username === req.user.username);
    if (!member || (member.role !== "nauczyciel" && req.user.role !== "admin")) return res.status(403).json({ message: "Brak uprawnień" });
    section.notes = (section.notes || []).filter(n => n.id.toString() !== noteId.toString());
    saveSections(sections);
    res.json({ message: "Usunięto lekcję" });
});

// --- SYSTEM FEEDBACKU ---

app.post("/add-feedback", auth, (req, res) => {
    const { code, lessonName, message } = req.body;
    let sections = loadSections();
    const section = sections.find(s => s.code === code);
    if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
    if (!section.feedbacks) section.feedbacks = [];
    const users = loadUsers();
    const currentUser = users.find(u => u.username === req.user.username);
    const authorName = currentUser && currentUser.name ? currentUser.name : req.user.username;
    section.feedbacks.push({
        id: Date.now(),
        lessonName,
        message,
        author: authorName,
        username: req.user.username,
        date: new Date().toLocaleString("pl-PL")
    });
    saveSections(sections);
    res.json({ message: "Wysłano!" });
});

app.get("/section-feedback/:code", auth, (req, res) => {
    const sections = loadSections();
    const section = sections.find(s => s.code === req.params.code);
    if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
    const member = section.members.find(m => m.username === req.user.username);
    const isTeacher = member && member.role === "nauczyciel";
    const isAdmin = req.user.role === "admin";
    const allFbs = section.feedbacks || [];
    // Jeśli nauczyciel/admin -> widzi wszystko. Jeśli uczeń -> widzi tylko swoje.
    if (isTeacher || isAdmin) {
        res.json(allFbs);
    } else {
        res.json(allFbs.filter(f => f.username === req.user.username));
    }
});

app.post("/edit-feedback", auth, (req, res) => {
    const { code, lessonName, newMessage } = req.body;
    let sections = loadSections();
    const section = sections.find(s => s.code === code);
    if (!section || !section.feedbacks) return res.status(404).json({ message: "Błąd" });
    // Szukamy konkretnego wpisu tego usera do tej lekcji
    const feedback = section.feedbacks.find(f => f.username === req.user.username && f.lessonName === lessonName);
    if (!feedback) return res.status(404).json({ message: "Nie znaleziono Twojej opinii" });
    feedback.message = newMessage;
    feedback.edited = true;
    feedback.date = new Date().toLocaleString("pl-PL") + " (edytowano)";
    saveSections(sections);
    res.json({ message: "Zaktualizowano!" });
});
app.post("/promote-to-teacher", auth, (req, res) => {
    const { code, targetUsername } = req.body;
    let sections = loadSections();
    const section = sections.find(s => s.code === code);

    if (!section) return res.status(404).json({ message: "Nie znaleziono sekcji" });

    // Pobieramy dane o użytkowniku wewnątrz sekcji
    const meInSection = section.members.find(m => m.username === req.user.username);
    
    // SPRAWDZENIE: Czy jest adminem globalnym I nauczycielem sekcji?
    const isGlobalAdmin = req.user.role === "admin";
    const isSectionTeacher = meInSection && meInSection.role === "nauczyciel";

    if (!(isGlobalAdmin && isSectionTeacher)) {
        return res.status(403).json({ message: "Musisz być jednocześnie Adminem i Nauczycielem sekcji, aby to zrobić." });
    }

    const targetMember = section.members.find(m => m.username === targetUsername);
    if (!targetMember) return res.status(404).json({ message: "Użytkownik nie należy do tej sekcji" });

    targetMember.role = "nauczyciel";
    saveSections(sections);
    res.json({ message: `Użytkownik ${targetUsername} został mianowany nauczycielem!` });
});
// --- INNE ---

app.post("/reset", auth, admin, (req, res) => {
    let users = loadUsers();
    saveUsers(users.filter(u => u.role === "admin"));
    saveSections([]);
    res.send("Baza zresetowana");
});
// --- SYSTEM PYTAŃ (KONWERSACJE) ---

// 1. Rozpoczęcie nowego wątku
app.post("/ask-question", auth, (req, res) => {
    const { code, subject, question, recipients } = req.body; 
    let sections = loadSections();
    const section = sections.find(s => s.code === code);

    if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
    if (!section.questions) section.questions = [];

    const users = loadUsers();
    const me = users.find(u => u.username === req.user.username);

    section.questions.push({
        id: Date.now().toString(), 
        from: me.name || me.username,
        fromUsername: me.username,
        subject: subject || "Brak tematu",
        text: question,
        to: recipients, 
        date: new Date().toLocaleString("pl-PL"),
        replies: [] 
    });

    saveSections(sections);
    res.json({ message: "Pytanie wysłane!" });
});

// 2. Pobieranie listy wątków
app.get("/section-questions/:code", auth, (req, res) => {
    const sections = loadSections();
    const section = sections.find(s => s.code === req.params.code);
    if (!section) return res.status(404).json({ message: "Błąd" });

    const allQs = section.questions || [];
    const myUsername = req.user.username;

    // Widzisz wątek jeśli go zacząłeś LUB jeśli jesteś odbiorcą (nauczycielem)
    const filtered = allQs.filter(q => 
        q.fromUsername === myUsername || q.to.includes(myUsername)
    );

    res.json(filtered);
});

// 3. Odpowiedź w istniejącym wątku
app.post("/reply-question", auth, (req, res) => {
    const { code, questionId, text } = req.body;
    let sections = loadSections();
    const section = sections.find(s => s.code === code);

    if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });

    const question = (section.questions || []).find(q => q.id === questionId || q.id.toString() === questionId);
    if (!question) return res.status(404).json({ message: "Nie znaleziono wątku" });

    const users = loadUsers();
    const me = users.find(u => u.username === req.user.username);

    if (!question.replies) question.replies = [];

    question.replies.push({
        from: me.name || me.username,
        fromUsername: me.username,
        text: text,
        date: new Date().toLocaleString("pl-PL")
    });

    saveSections(sections);
    res.json({ message: "Dodano odpowiedź!" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Serwer działa na porcie " + PORT));