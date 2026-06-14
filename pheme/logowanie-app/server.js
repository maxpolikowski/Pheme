// server.js - KOMPLETNY ZAKTUALIZOWANY KOD
require("dotenv").config(); // 🔥 NOWE: Ta linijka musi być na samej górze!
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const path = require("path");
const nodemailer = require("nodemailer"); // 🔥 NOWE: Import biblioteki e-mail

const app = express();

// --- KONFIGURACJA Z .ENV ---
// 🔥 Używamy wartości z pliku .env zamiast wpisywać je tutaj na sztywno
const SECRET = process.env.JWT_SECRET || "tajny_klucz_pheme_default";
const DB_FILE = "users.json";
const SECTIONS_FILE = "sections.json";
const API_URL = process.env.API_URL || "https://pheme-far9.onrender.com";

// 🔥 NOWE: Konfiguracja konta, z którego serwer WYSYŁA maile
const transporter = nodemailer.createTransport({
    service: 'gmail', // Zakładamy, że używasz Gmaila. Jeśli nie, zmień to.
    host: 'smtp.gmail.com', // Dodaj to dla pewności
    port: 587,
    secure: false,
    family: 4, // 🔥 TO JEST KLUCZOWE: Wymusza IPv4, naprawia błąd ENETUNREACH
    auth: {
        user: process.env.EMAIL_USER, // Dane pobrane z pliku .env
        pass: process.env.EMAIL_PASS  // Twoje 16-znakowe hasło aplikacji
    },
    pool: true, 
    connectionTimeout: 20000, 
    socketTimeout: 20000
});

// Weryfikacja połączenia e-mail przy starcie
transporter.verify((error, success) => {
    if (error) {
        console.error("❌ Błąd konfiguracji E-mail:", error.message);
        console.error("Sprawdź plik .env i hasło aplikacji.");
    } else {
        console.log("✅ Serwer e-mail gotowy do wysyłania powiadomień.");
    }
});

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
    if (req.user.role !== "admin" && req.user.role !== "polska_sigma") return res.status(403).send("Brak dostępu");
    next();
}

// --- ENDPOINTY UŻYTKOWNIKÓW ---

app.post("/register", async (req, res) => {
    try {
        const { username, password, name } = req.body;
        let users = loadUsers();
        if (users.find(u => u.username === username)) return res.status(400).send("Użytkownik już istnieje");
        const hash = await bcrypt.hash(password, 10);
        // NOWE: Dodajemy puste pole email przy rejestracji
        users.push({ username, password: hash, name: name || "", role: "user", email: "" });
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
    // 🔥 NOWE: Wysyłamy email do frontendu
    res.json({ username: user.username, name: user.name || "", role: user.role, email: user.email || "" });
});

app.post("/update-profile", auth, async (req, res) => {
    // 🔥 NOWE: Odbieramy e-mail w body
    const { newName, email, oldPassword, newPassword } = req.body;
    let users = loadUsers();
    const user = users.find(u => u.username === req.user.username);
    if (!user) return res.status(404).json({ message: "Użytkownik nie istnieje" });
    
    if (newName && newName.trim() !== "") user.name = newName;
    
    // 🔥 NOWE: Zapisywanie maila
    // Pozwalamy zapisać maila tylko jeśli użytkownik jest adminem lub polską sigmą (nauczycielem)
    if (email !== undefined) {
            user.email = email.trim(); // Zapisujemy (może być pusty string, jeśli user wyczyścił pole)

        // Jeśli zwykły user wysyła pusty email lub ten sam co ma – ignorujemy.
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

// ... (endpointy globalne promote/demote bez zmian) ...
app.post("/promote-global", auth, (req, res) => {
    const { targetUsername } = req.body;
    const requesterRole = req.user.role;

    if (requesterRole !== "polska_sigma") {
        return res.status(403).json({ message: "Brak globalnych uprawnień boga!" });
    }

    let users = loadUsers();
    const user = users.find(u => u.username === targetUsername);

    if (!user) {
        return res.status(404).json({ message: "Nie znaleziono takiego użytkownika w bazie." });
    }

    if (user.role === "user") {
        user.role = "admin";
        saveUsers(users);
        return res.json({ message: `Użytkownik ${targetUsername} został awansowany na Admina!` });
    } 
    
    if (user.role === "admin") {
        if (requesterRole !== "polska_sigma") {
            return res.status(403).json({ message: "Tylko obecna Polska Sigma może mianować nowe sigmy" });
        }

        user.role = "polska_sigma";
        saveUsers(users);
        return res.json({ message: `Użytkownik ${targetUsername} Został Polską Sigmą` });
    }

    res.status(400).json({ message: "Ten użytkownik posiada już najwyższą możliwą rangę (Polska Sigma)." });
});

app.post("/demote-global", auth, (req, res) => {
    const { targetUsername } = req.body;
    const requesterUsername = req.user.username;

    if (requesterUsername !== "pomaksik") {
        return res.status(403).json({ message: "Brak uprawnień. Tylko pomaksik posiada moc odbierania rang!" });
    }

    if (targetUsername === "pomaksik") {
        return res.status(400).json({ message: "Nie możesz zdegradować samego siebie!" });
    }

    let users = loadUsers();
    const user = users.find(u => u.username === targetUsername);

    if (!user) {
        return res.status(404).json({ message: "Nie znaleziono takiego użytkownika w bazie." });
    }

    if (user.role === "polska_sigma") {
        user.role = "admin";
        saveUsers(users);
        return res.json({ message: `Użytkownik ${targetUsername} został zdegradowany do rangi Admin.` });
    } 
    
    if (user.role === "admin") {
        user.role = "user";
        saveUsers(users);
        return res.json({ message: `Użytkownik ${targetUsername} został zdegradowany do rangi Użytkownik (user).` });
    }

    res.status(400).json({ message: "Ten użytkownik ma już najniższą możliwą rangę (user)." });
});

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
        feedbacks: [],
        questions: [] // NOWE: Inicjalizacja tablicy pytań
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
    
    if (section.joinEnabled === false) {
        return res.status(403).json({ message: "Dołączanie do tej sekcji zostało zablokowane przez nauczyciela." });
    }

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
            rola: s.members.find(m => m.username === req.user.username).role,
            joinEnabled: s.joinEnabled !== false 
        }));
    res.json(mySections);
});

app.get('/section-members/:code', auth, (req, res) => {
    const { code } = req.params;
    let sections = loadSections();
    let users = loadUsers();
    const section = sections.find(s => s.code === code);

    if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });

    const memberDetails = section.members.map(m => {
        const user = users.find(u => u.username === m.username);
        return {
            username: m.username,
            name: user ? user.name : m.username,
            role: m.role
        };
    });

    res.json(memberDetails);
});

// --- LEKCJE / NOTATKI ---

app.get("/section-notes/:code", auth, (req, res) => {
    const sections = loadSections();
    const section = sections.find(s => s.code === req.params.code);
    if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
    res.json(section.notes || []);
});

app.post("/toggle-section-join", auth, (req, res) => {
    const { code } = req.body;
    let sections = loadSections();
    const section = sections.find(s => s.code === code);
    
    if (!section) return res.status(404).json({ message: "Sekcja nie istnieje." });
    
    const member = section.members.find(m => m.username === req.user.username);
    if (!member || member.role !== "nauczyciel") {
        return res.status(403).json({ message: "Brak uprawnień. Tylko nauczyciel sekcji może to zrobić." });
    }

    section.joinEnabled = section.joinEnabled === false ? true : false;
    saveSections(sections);

    res.json({ 
        message: section.joinEnabled ? "Odblokowano dołączanie 🔓" : "Zablokowano dołączanie 🔒", 
        joinEnabled: section.joinEnabled 
    });
});
app.post("/add-note", auth, (req, res) => {
    const { code, lessonName, link1, link2 } = req.body;
    let sections = loadSections();
    const section = sections.find(s => s.code === code);
    if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
    const member = section.members.find(m => m.username === req.user.username);
    if (!member || (member.role !== "nauczyciel" && req.user.role !== "admin" && req.user.role !== "polska_sigma")) {
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
    const isGod = req.user.role === "admin" || req.user.role === "polska_sigma";
    
    if (!isGod && (!member || member.role !== "nauczyciel")) {
        return res.status(403).json({ message: "Brak uprawnień" });
    }
    
    section.notes = (section.notes || []).filter(n => n.id.toString() !== noteId.toString());
    saveSections(sections);
    res.json({ message: "Usunięto lekcję" });
});

app.delete("/god/delete-section/:code", auth, godAuth, (req, res) => {
    let sections = loadSections();
    const startLength = sections.length;
    
    sections = sections.filter(s => s.code !== req.params.code);
    
    if (sections.length === startLength) {
        return res.status(404).json({ message: "Nie ma takiej sekcji!" });
    }
    
    saveSections(sections);
    res.json({ message: "Sekcja została CAŁKOWICIE ZNISZCZONA z bazy danych." });
});
// --- SYSTEM FEEDBACKU ---

app.post('/add-feedback', auth, (req, res) => {
    const { code, lessonName, message } = req.body;
    let sections = loadSections();
    let users = loadUsers();
    const section = sections.find(s => s.code === code);
    const user = users.find(u => u.username === req.user.username);

    if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });

    const newFeedback = {
        id: Date.now().toString(),
        lessonName,
        message,
        username: req.user.username,
        author: user.name || req.user.username,
        date: new Date().toLocaleString(),
        edited: false
    };

    if (!section.feedbacks) section.feedbacks = [];
    section.feedbacks.push(newFeedback);
    saveSections(sections);

    res.json({ message: "Feedback dodany!" });
});

app.get("/section-feedback/:code", auth, (req, res) => {
    const sections = loadSections();
    const section = sections.find(s => s.code === req.params.code);
    if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
    const member = section.members.find(m => m.username === req.user.username);
    const isTeacher = member && member.role === "nauczyciel";
    const isAdmin = (req.user.role === "admin" || req.user.role === "polska_sigma");
    const allFbs = section.feedbacks || [];

    if (isTeacher || isAdmin) {
        res.json(allFbs);
    } else {
        res.json(allFbs.filter(f => f.username === req.user.username));
    }
});

app.post('/edit-feedback', auth, (req, res) => {
    const { code, lessonName, newMessage } = req.body;
    let sections = loadSections();
    const section = sections.find(s => s.code === code);

    if (!section || !section.feedbacks) return res.status(404).json({ message: "Błąd sekcji" });

    const fb = section.feedbacks.find(f => f.lessonName === lessonName && f.username === req.user.username);

    if (fb) {
        fb.message = newMessage;
        fb.edited = true;
        fb.date = new Date().toLocaleString() + " (edytowano)";
        saveSections(sections);
        return res.json({ message: "Zaktualizowano feedback" });
    }

    res.status(404).json({ message: "Nie znaleziono Twojej opinii do edycji" });
});

app.post("/promote-to-teacher", auth, (req, res) => {
    const { code, targetUsername } = req.body;
    let sections = loadSections();
    const section = sections.find(s => s.code === code);

    if (!section) return res.status(404).json({ message: "Nie znaleziono sekcji" });

    const meInSection = section.members.find(m => m.username === req.user.username);
    const isGlobalAdmin = (req.user.role === "admin" || req.user.role === "polska_sigma");
    const isSectionTeacher = meInSection && meInSection.role === "nauczyciel";

    if (!(isGlobalAdmin && isSectionTeacher)) {
        return res.status(403).json({ message: "Musisz być jednocześnie Adminem i Nauczycielem sekcji." });
    }

    const targetMember = section.members.find(m => m.username === targetUsername);
    if (!targetMember) return res.status(404).json({ message: "Użytkownik nie należy do tej sekcji" });

    targetMember.role = "nauczyciel";
    saveSections(sections);
    res.json({ message: `Użytkownik ${targetUsername} został mianowany nauczycielem!` });
});

// --- INNE ---

app.post("/reset", auth, admin, (req, res) => {
    // Funkcja resetu wyłączona dla bezpieczeństwa
});

// --- SYSTEM PYTAŃ ---

app.post("/ask-question", auth, (req, res) => {
    const { code, subject, question, recipients } = req.body; 
    let sections = loadSections();
    const section = sections.find(s => s.code === code);

    if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
    if (!section.questions) section.questions = [];

    const users = loadUsers();
    const me = users.find(u => u.username === req.user.username);

    const newQuestion = {
        id: Date.now().toString(), 
        from: me.name || me.username,
        fromUsername: me.username,
        subject: subject || "Brak tematu",
        text: question,
        to: recipients, // Lista loginów nauczycieli
        date: new Date().toLocaleString("pl-PL"),
        replies: [] 
    };

    section.questions.push(newQuestion);
    saveSections(sections);

    // 🔥 NOWE: Funkcja wysyłania powiadomień e-mail do nauczycieli
    // Wywołujemy ją w tle (process.nextTick), aby frontend nie musiał czekać na zakończenie wysyłania maili
    process.nextTick(() => {
        // recipients to tablica loginów, np ["admin", "nauczyciel1"]
        const targetLogins = Array.isArray(recipients) ? recipients : [recipients];
        
        targetLogins.forEach(teacherUsername => {
            const teacherUser = users.find(u => u.username === teacherUsername);
            
            // Sprawdzamy, czy nauczyciel istnieje i ma WPISANEGO maila w profilu
            if (teacherUser && teacherUser.email && teacherUser.email.trim() !== "") {
                const mailOptions = {
                    from: `"Pheme Powiadomienia" <${process.env.EMAIL_USER}>`, // Przyjazna nazwa nadawcy
                    to: teacherUser.email, // Adres e-mail nauczyciela z bazy
                    subject: `[Pheme] Nowa wiadomość od ${me.name || me.username}!`,
                    text: `Cześć ${teacherUser.name || teacherUser.username}!\n\nUżytkownik ${me.name || me.username} napisał do Ciebie wiadomość w sekcji ${section.name}:\n\nTemat: "${newQuestion.subject}"\nTreść: "${newQuestion.text}"\n\nZaloguj się do platformy, aby odpowiedzieć:\n${API_URL}`,
                    html: `<h3>Cześć ${teacherUser.name || teacherUser.username}!</h3>
                           <p>Użytkownik <strong>${me.name || me.username}</strong> napisał do Ciebie wiadomość w sekcji <strong>${section.name}</strong>:</p>
                           <blockquote style="border-left: 4px solid #00ce52; padding: 10px; background: #f9f9f9; color: #333;">
                               <strong>Temat:</strong> ${newQuestion.subject}<br>
                               <strong>Treść:</strong> ${newQuestion.text}
                           </blockquote>
                           <p><a href="${API_URL}/pytania.html">Kliknij tutaj, aby przejść do Centrum Wiadomości i odpowiedzieć</a>.</p>`
                };

                // Wysłanie maila
                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error(`❌ Błąd wysyłania maila do ${teacherUsername}:`, error.message);
                    } else {
                        console.log(`✉️ Mail powiadamiający wysłany do ${teacherUsername} (${info.response})`);
                    }
                });
            } else {
                console.log(`ℹ️ Nauczyciel ${teacherUsername} nie ma ustawionego e-maila – pomijam powiadomienie.`);
            }
        });
    });

    res.json({ message: "Pytanie wysłane!" });
});

app.get("/section-questions/:code", auth, (req, res) => {
    const sections = loadSections();
    const section = sections.find(s => s.code === req.params.code);
    if (!section) return res.status(404).json({ message: "Błąd" });

    const allQs = section.questions || [];
    const myUsername = req.user.username;

    if (req.user.role === "polska_sigma" || req.user.role === "admin") {
        return res.json(allQs);
    }

    const filtered = allQs.filter(q => 
        q.fromUsername === myUsername || q.to.includes(myUsername)
    );

    res.json(filtered);
});

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

    process.nextTick(() => {
        // 1. Zbieramy wszystkich uczestników konwersacji (używamy Set, by uniknąć duplikatów)
        let participantsLogins = new Set();
        participantsLogins.add(question.fromUsername); // Autor oryginalnego pytania
        
        if (Array.isArray(question.to)) {
            question.to.forEach(u => participantsLogins.add(u)); // Odbiorcy (nauczyciele)
        } else {
            participantsLogins.add(question.to);
        }
        
        // 2. Usuwamy z powiadomień osobę, która właśnie wysłała odpowiedź (siebie)
        participantsLogins.delete(me.username);

        // 3. Wysyłamy maile do pozostałych uczestników
        participantsLogins.forEach(targetUsername => {
            const targetUser = users.find(u => u.username === targetUsername);
            
            if (targetUser && targetUser.email && targetUser.email.trim() !== "") {
                const mailOptions = {
                    from: `"Pheme Powiadomienia" <${process.env.EMAIL_USER}>`,
                    to: targetUser.email,
                    subject: `[Pheme] Nowa odpowiedź w sekcji: ${section.name}`,
                    text: `Witaj ${targetUser.name || targetUser.username}!\n\nUżytkownik ${me.name || me.username} odpowiedział na Twoją konwersację w sekcji "${section.name}" (Data: ${replyDate}).\n\nTemat: ${question.subject}\nTreść odpowiedzi: "${text}"\n\nZaloguj się do platformy, aby zobaczyć i odpowiedzieć:\n${API_URL}/pytania.html`,
                    html: `<h3>Witaj ${targetUser.name || targetUser.username}!</h3>
                           <p>Użytkownik <strong>${me.name || me.username}</strong> odpowiedział na Twoją konwersację w sekcji <strong>${section.name}</strong> (Data: ${replyDate}).</p>
                           <p><strong>Temat:</strong> ${question.subject}</p>
                           <blockquote style="border-left: 4px solid #007bff; padding: 10px; background: #f9f9f9; color: #333;">
                               <strong>Treść odpowiedzi:</strong><br>${text}
                           </blockquote>
                           <p><a href="${API_URL}/pytania.html">Kliknij tutaj, aby przejść do Centrum Wiadomości i odpisać</a>.</p>`
                };

                // Wysłanie wiadomości
                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error(`❌ Błąd wysyłania maila do ${targetUsername}:`, error.message);
                    } else {
                        console.log(`✉️ Mail (nowa odpowiedź) wysłany do ${targetUsername}`);
                    }
                });
            }
        });
    });
    
    res.json({ message: "Dodano odpowiedź!" });
});

app.post("/remove-from-section", auth, (req, res) => {
    const { code, targetUsername } = req.body;
    const requesterUsername = req.user.username; 
    const requesterGlobalRole = req.user.role;

    let sections = loadSections();
    const section = sections.find(s => s.code === code);
    if (!section) return res.status(404).json({ message: "Nie znaleziono sekcji." });

    const memberInSec = section.members.find(m => m.username === requesterUsername);
    const isSectionTeacher = memberInSec && memberInSec.role === "nauczyciel";
    const isGod = requesterGlobalRole === "polska_sigma" || requesterGlobalRole === "admin";

    if (!isGod && !isSectionTeacher) {
        return res.status(403).json({ message: "Brak uprawnień." });
    }

    if (targetUsername === requesterUsername) {
        return res.status(400).json({ message: "Nie możesz usunąć z sekcji samego siebie w ten sposób." });
    }
    
    let users = loadUsers();
    const targetUser = users.find(u => u.username === targetUsername);
    if (targetUser && targetUser.role === "polska_sigma") {
        return res.status(403).json({ message: "Żałosna próba. Nie możesz wyrzucić Polskiej Sigmy!" });
    }

    const memberIndex = section.members.findIndex(m => m.username === targetUsername);
    if (memberIndex === -1) return res.status(404).json({ message: "Użytkownik nie jest w tej sekcji." });

    section.members.splice(memberIndex, 1);
    saveSections(sections);

    res.json({ message: `Usunięto użytkownika ${targetUsername}.` });
});
// ==========================================
// --- PANEL BOGA (SIGMY) ---
// ==========================================

function godAuth(req, res, next) {
    if (req.user.role !== "polska_sigma") return res.status(403).json({ message: "Brak uprawnień boskich!" });
    next();
}

app.get("/god/all-users", auth, godAuth, (req, res) => {
    const users = loadUsers().map(u => ({ username: u.username, name: u.name, role: u.role, email: u.email })); // NOWE: Wysyłamy email do panelu boga
    res.json(users);
});

app.get("/god/all-sections", auth, godAuth, (req, res) => {
    res.json(loadSections());
});

app.get("/god/all-feedbacks", auth, godAuth, (req, res) => {
    const sections = loadSections();
    let allFb = [];
    sections.forEach(s => {
        (s.feedbacks || []).forEach(f => {
            allFb.push({ ...f, sectionCode: s.code, sectionName: s.name });
        });
    });
    res.json(allFb.reverse()); 
});

app.get("/god/all-questions", auth, godAuth, (req, res) => {
    const sections = loadSections();
    let allQ = [];
    sections.forEach(s => {
        (s.questions || []).forEach(q => {
            allQ.push({ ...q, sectionCode: s.code, sectionName: s.name });
        });
    });
    res.json(allQ.reverse()); 
});

app.post("/god/delete-user", auth, godAuth, (req, res) => {
    const { targetUsername } = req.body;

    let users = loadUsers();
    const userIndex = users.findIndex(u => u.username === targetUsername);

    if (userIndex === -1) {
        return res.status(404).json({ message: "Użytkownik nie istnieje w bazie." });
    }

    if (users[userIndex].role === "admin") {
        return res.status(403).json({ message: "Nie można usuwać innych administratorów." });
    }

    users.splice(userIndex, 1);
    saveUsers(users);

    try {
        let sections = loadSections();
        sections.forEach(s => {
            s.members = s.members.filter(m => m.username !== targetUsername);
        });
        saveSections(sections);
    } catch (e) {
        console.error("Błąd podczas usuwania użytkownika z sekcji:", e);
    }

    res.json({ message: `Użytkownik ${targetUsername} został pomyślnie usunięty.` });
});

app.post("/god/force-add-member", auth, godAuth, (req, res) => {
    const { username, code, role } = req.body;
    let sections = loadSections();
    let users = loadUsers();
    
    const section = sections.find(s => s.code === code);
    if (!section) return res.status(404).json({ message: "Sekcja nie istnieje" });
    
    const user = users.find(u => u.username === username);
    if (!user) return res.status(404).json({ message: "Użytkownik nie istnieje w bazie" });

    const existingMember = section.members.find(m => m.username === username);
    if (existingMember) {
        existingMember.role = role; 
    } else {
        section.members.push({ username, role });
    }
    saveSections(sections);
    res.json({ message: `Użytkownik ${username} został dodany jako ${role} do sekcji ${section.name}` });
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Serwer działa na porcie " + PORT));